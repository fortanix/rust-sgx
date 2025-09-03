/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;
pub mod debugging;

use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Error as IoError, Result as IoResult};
use std::ops::Range;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use nix::sys::mman::{mmap, munmap, ProtFlags as Prot, MapFlags as Map};
use nix::errno::Errno;

use sgx_isa::{Attributes, Einittoken, ErrorCode, Miscselect, Secinfo, Secs, Sigstruct, PageType, SecinfoFlags};
use sgxs::einittoken::EinittokenProvider;
use sgxs::loader;
use sgxs::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};
use thiserror::Error as ThisError;

use crate::{MappingInfo, Tcs};
use crate::generic::{self, EinittokenError, EnclaveLoad, Mapping};

/// A Linux SGX driver API family.
///
/// Unfortunately, there are many different driver versions that all have a
/// slightly different API and may also have slightly different functionality.
/// There is no common versioning or naming scheme for referring to these
/// drivers. These are grouped here into different families of APIs, each
/// family represents a set of interfaces that are very similar, and as such
/// can be called by similar logic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DriverFamily {
    /// These APIs are commonly exposed via device nodes at
    /// * `/dev/isgx`
    /// * `/dev/sgx`
    /// * `/dev/sgx_prv`
    ///
    /// # Compatibility notes
    ///
    /// Implementations may require a launch token, may not support providing a
    /// launch token, or may provide both as an option.
    Montgomery,
    /// This API is commonly exposed via a device node at
    /// * `/dev/sgx/enclave`
    /// * `/dev/sgx_enclave`
    ///
    /// # Compatibility notes
    ///
    /// Currently, no upstream implementations of this API family support
    /// partially-measured pages or providing a launch token. A Fortanix internal
    /// SGX driver explicitly adds support for partially-measured pages for backwards
    /// compatibility reasons.
    Augusta,
}

use self::DriverFamily::*;

#[derive(ThisError, Debug)]
pub enum SgxIoctlError {
    #[error("I/O ctl failed.")]
    Io(#[source] IoError),
    #[error("The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
    #[error("The enclave was destroyed because the CPU was powered down.")]
    PowerLostEnclave,
    #[error("Launch enclave version rollback detected.")]
    LeRollback,
}

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to map enclave into memory.")]
    Map(#[source] IoError),
    #[error("Failed to call ECREATE.")]
    Create(#[source] SgxIoctlError),
    #[error("Failed to call EADD.")]
    Add(#[source] SgxIoctlError),
    #[error("Failed to call EEXTEND.")]
    Extend(#[source] SgxIoctlError),
    #[error("Failed to call EINIT.")]
    Init(#[source] SgxIoctlError),
}

impl Error {
    fn map(error: nix::Error) -> Self {
        Error::Map(error.as_errno().unwrap().into())
    }
}

impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        use self::Error::Init;
        use self::SgxIoctlError::Ret;
        match self {
            &Init(Ret(ErrorCode::InvalidEinitToken)) |
            &Init(Ret(ErrorCode::InvalidCpusvn)) |
            &Init(Ret(ErrorCode::InvalidAttribute)) | // InvalidEinitAttribute according to PR, but does not exist.
            &Init(Ret(ErrorCode::InvalidMeasurement)) => true,
            _ => false,
        }
    }
}

macro_rules! ioctl_unsafe {
    ( $f:ident, $v:expr ) => {{
        const SGX_POWER_LOST_ENCLAVE: i32 = 0x40000000;
        const SGX_LE_ROLLBACK: i32 = 0x40000001;

        match unsafe { $v } {
            Err(_) => Err(Error::$f(SgxIoctlError::Io(IoError::last_os_error()))),
            Ok(0) => Ok(()),
            Ok(SGX_POWER_LOST_ENCLAVE) => Err(Error::$f(SgxIoctlError::PowerLostEnclave)),
            Ok(SGX_LE_ROLLBACK) => Err(Error::$f(SgxIoctlError::LeRollback)),
            Ok(v) => Err(Error::$f(SgxIoctlError::Ret(
                ErrorCode::try_from(v as u32).expect("Invalid ioctl return value"),
            ))),
        }
    }};
}

impl EnclaveLoad for InnerDevice {
    type Error = Error;
    type MapData = MapData;

    fn new(
        mut device: Arc<InnerDevice>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let esize = ecreate.size as usize;
        let ptr = unsafe {
            match device.driver {
                Montgomery => {
                    mmap(
                        ptr::null_mut(),
                        esize,
                        Prot::PROT_READ | Prot::PROT_WRITE | Prot::PROT_EXEC,
                        Map::MAP_SHARED,
                        device.fd.as_raw_fd(),
                        0,
                    ).map_err(Error::map)?
                },
                Augusta => {
                    unsafe fn maybe_unmap(addr: *mut std::ffi::c_void, len: usize) {
                        if len == 0 {
                            return;
                        }
                        if let Err(e) = munmap(addr, len) {
                            eprintln!("SGX enclave create: munmap failed: {:?}", e);
                        }
                    }

                    // re-open device by cloning, if necessary
                    Arc::make_mut(&mut device);

                    let ptr = mmap(
                        ptr::null_mut(),
                        esize * 2,
                        Prot::PROT_NONE,
                        Map::MAP_SHARED | Map::MAP_ANONYMOUS | Map::MAP_NORESERVE,
                        0,
                        0,
                    ).map_err(Error::map)?;

                    let align_offset = ptr.align_offset(esize);
                    if align_offset > esize {
                        unreachable!()
                    }
                    let newptr = ptr.add(align_offset);
                    maybe_unmap(ptr, align_offset);
                    maybe_unmap(newptr.add(esize), esize - align_offset);

                    newptr
                },
            }
        };

        let mapping = Mapping {
            device,
            mapdata: Default::default(),
            base: ptr as u64,
            size: ecreate.size,
            tcss: vec![],
        };
        debugging::register_new_enclave(mapping.base, mapping.size);

        let secs = Secs {
            baseaddr: mapping.base,
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };
        let createdata = ioctl::CreateData { secs: &secs };
        ioctl_unsafe!(
            Create,
            ioctl::create(mapping.device.fd.as_raw_fd(), &createdata)
        )?;
        Ok(mapping)
    }

    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {
        let (eadd, chunks, data) = page;
        let secinfo = Secinfo {
            flags: eadd.secinfo.flags,
            ..Default::default()
        };
        let dstpage = mapping.base + eadd.offset;
        match mapping.device.driver {
            Montgomery => {
                let adddata = ioctl::montgomery::AddData {
                    dstpage,
                    srcpage: &data,
                    secinfo: &secinfo,
                    chunks: chunks.0,
                };
                ioctl_unsafe!(Add, ioctl::montgomery::add(mapping.device.fd.as_raw_fd(), &adddata))
            },
            Augusta => {
                let (flags, partially_measured) = match chunks.0 {
                    0 => (ioctl::augusta::SgxPageFlags::empty(), false),
                    0xffff => (ioctl::augusta::SgxPageFlags::SGX_PAGE_MEASURE, false),
                    _ => (ioctl::augusta::SgxPageFlags::empty(), true)
                };

                let data = ioctl::augusta::Align4096(data);
                let mut adddata = ioctl::augusta::AddData {
                    src: &data,
                    offset: eadd.offset,
                    length: data.0.len() as _,
                    secinfo: &secinfo,
                    flags,
                    count: 0,
                };
                ioctl_unsafe!(Add, ioctl::augusta::add(mapping.device.fd.as_raw_fd(), &mut adddata))?;
                assert_eq!(adddata.length, adddata.count);

                if partially_measured {
                    for chunk in 0..16 {
                        if (0x1 << chunk) & chunks.0 != 0 {
                            // Only supported with Fortanix' internal upstream driver patch
                            let mut extend = ioctl::augusta::SgxEnclaveExtend {
                                offset: eadd.offset as u64 + chunk as u64 * 256,
                            };
                            let fd = mapping.device.fd.as_raw_fd();
                            ioctl_unsafe!(Extend, ioctl::augusta::extend(fd, &mut extend))
                                .or_else(|e| {
                                    match e {
                                        Error::Extend(SgxIoctlError::Io(ref io_err)) if io_err.raw_os_error() == Some(Errno::ENOTTY as i32) => {
                                            return Err(Error::Add(SgxIoctlError::Io(IoError::new(
                                                io::ErrorKind::Other,
                                                "Partially-measured pages not supported in this driver",
                                            ))))
                                        }
                                        _ => Err(e),
                                    }
                                })?;
                        }
                    }
                }

                let prot = match PageType::try_from(secinfo.flags.page_type()) {
                    Ok(PageType::Reg) => {
                        let mut prot = Prot::empty();
                        if secinfo.flags.intersects(SecinfoFlags::R) {
                            prot |= Prot::PROT_READ
                        }
                        if secinfo.flags.intersects(SecinfoFlags::W) {
                            prot |= Prot::PROT_WRITE
                        }
                        if secinfo.flags.intersects(SecinfoFlags::X) {
                            prot |= Prot::PROT_EXEC
                        }
                        prot
                    }
                    Ok(PageType::Tcs) => {
                        Prot::PROT_READ | Prot::PROT_WRITE
                    },
                    _ => unreachable!(),
                };

                let range = dstpage..(dstpage + data.0.len() as u64);

                impl PendingMmap {
                    fn append(&mut self, prot: Prot, range: &Range<u64>) -> bool {
                        let can_append = prot == self.prot && self.range.end == range.start;
                        if can_append {
                            self.range.end = range.end;
                        }
                        can_append
                    }
                }

                let (pending, map_now) = match mapping.mapdata.pending_mmap.take() {
                    Some(mut pending_mmap) => {
                        if pending_mmap.append(prot, &range) {
                            (Some(pending_mmap), None)
                        } else {
                            (None, Some(pending_mmap))
                        }
                    },
                    None => (None, None)
                };

                mapping.mapdata.pending_mmap = Some(pending.unwrap_or(PendingMmap { prot, range }));
                if let Some(map_now) = map_now {
                    unsafe { map_now.map(&mapping.device)? };
                }

                Ok(())
            }
        }
    }

    fn init(
        mapping: &mut Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        // ioctl() may return ENOTTY if the specified request does not apply to
        // the kind of object that the descriptor fd references.
        fn is_enotty(result: &Result<(), Error>) -> bool {
            match result {
                Err(Error::Init(SgxIoctlError::Io(ref err))) => {
                    err.raw_os_error() == Some(Errno::ENOTTY as _)
                }
                _ => false,
            }
        }

        fn ioctl_init(mapping: &Mapping<InnerDevice>, sigstruct: &Sigstruct) -> Result<(), Error> {
            match mapping.device.driver {
                Montgomery => {
                    let initdata = ioctl::montgomery::InitData {
                        base: mapping.base,
                        sigstruct,
                    };
                    ioctl_unsafe!(Init, ioctl::montgomery::init(mapping.device.fd.as_raw_fd(), &initdata))
                },
                Augusta => {
                    let initdata = ioctl::augusta::InitData {
                        sigstruct,
                    };
                    ioctl_unsafe!(Init, ioctl::augusta::init(mapping.device.fd.as_raw_fd(), &initdata))
                }
            }
        }

        fn ioctl_init_with_token(
            mapping: &Mapping<InnerDevice>,
            sigstruct: &Sigstruct,
            einittoken: &Einittoken,
        ) -> Result<(), Error> {
            match mapping.device.driver {
                Montgomery => {
                    let initdata = ioctl::montgomery::InitDataWithToken {
                        base: mapping.base,
                        sigstruct,
                        einittoken,
                    };
                    ioctl_unsafe!(
                        Init,
                        ioctl::montgomery::init_with_token(mapping.device.fd.as_raw_fd(), &initdata)
                    )
                },
                Augusta => {
                    Err(Error::Init(SgxIoctlError::Io(Errno::ENOTTY.into())))
                }
            }
        }

        if let Some(pending_mmap) = mapping.mapdata.pending_mmap.take() {
            unsafe { pending_mmap.map(&mapping.device)? };
        }

        // Try either EINIT ioctl(), in the order that makes most sense given
        // the function arguments
        if let Some(einittoken) = einittoken {
            let res = ioctl_init_with_token(mapping, sigstruct, einittoken);

            if is_enotty(&res) {
                ioctl_init(mapping, sigstruct)
            } else {
                res
            }
        } else {
            let res = ioctl_init(mapping, sigstruct);

            if is_enotty(&res) {
                ioctl_init_with_token(mapping, sigstruct, &Default::default())
            } else {
                res
            }
        }
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        debugging::unregister_terminated_enclave(mapping.base);
        unsafe { let _ = munmap(mapping.base as usize as *mut _, mapping.size as usize); }
    }
}

#[derive(Debug)]
#[must_use]
struct PendingMmap {
    prot: Prot,
    range: Range<u64>,
}

impl PendingMmap {
    unsafe fn map(self, device: &InnerDevice) -> Result<(), Error> {
        mmap(
            self.range.start as _,
            (self.range.end - self.range.start) as _,
            self.prot,
            Map::MAP_SHARED | Map::MAP_FIXED,
            device.fd.as_raw_fd(),
            0,
        ).map(|_| ()).map_err(Error::map)
    }
}

#[derive(Debug, Default)]
struct MapData {
    pending_mmap: Option<PendingMmap>
}

#[derive(Debug)]
struct InnerDevice {
    fd: File,
    path: Arc<PathBuf>,
    driver: DriverFamily,
}

impl Clone for InnerDevice {
    fn clone(&self) -> Self {
        InnerDevice {
            fd: OpenOptions::new().read(true).write(true).open(&**self.path).unwrap(),
            path: self.path.clone(),
            driver: self.driver,
        }
    }
}

#[derive(Debug)]
pub struct Device {
    inner: generic::Device<InnerDevice>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<InnerDevice>,
}

impl Device {
    /// Try to open an SGX device from a list of default paths
    pub fn new() -> IoResult<DeviceBuilder> {
        const DEFAULT_DEVICE_PATHS: &[(&str, DriverFamily)] = &[
            ("/dev/sgx_enclave", Augusta),
            ("/dev/sgx/enclave", Augusta),
            ("/dev/isgx", Montgomery),
            ("/dev/sgx", Montgomery),
        ];

        for &(path, family) in DEFAULT_DEVICE_PATHS {
            match Self::open(path, family) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(ref e) if e.raw_os_error() == Some(Errno::ENOTDIR as _) => continue,
                result => return result,
            }
        }

        Err(IoError::new(io::ErrorKind::NotFound, "None of the default SGX device paths were found"))
    }

    pub fn open<T: AsRef<Path>>(path: T, driver: DriverFamily) -> IoResult<DeviceBuilder> {
        let path = path.as_ref();
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(InnerDevice {
                        fd: file,
                        path: Arc::new(path.to_owned()),
                        driver,
                    }),
                    einittoken_provider: None,
                },
            },
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.inner.path
    }
}

impl loader::Load for Device {
    type MappingInfo = MappingInfo;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::anyhow::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}

impl DeviceBuilder {
    pub fn einittoken_provider<P: Into<Box<dyn EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Device {
        Device {
            inner: self.inner.build(),
        }
    }
}
