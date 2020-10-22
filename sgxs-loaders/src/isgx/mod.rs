/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod ioctl;

use libc;
use std::convert::TryFrom;
use std::fs::{File, OpenOptions};
use std::io::{self, Error as IoError, Result as IoResult};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use nix::sys::mman::{mmap, munmap, ProtFlags as Prot, MapFlags as Map};

use sgx_isa::{Attributes, Einittoken, ErrorCode, Miscselect, Secinfo, Secs, Sigstruct, PageType, SecinfoFlags};
use sgxs::einittoken::EinittokenProvider;
use sgxs::loader;
use sgxs::loader::EnclaveControl;
use sgxs::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::{MappingInfo, Tcs};
use crate::isgx::ioctl::montgomery::SgxRange;
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
    ///
    /// # Compatibility notes
    ///
    /// Currently, no implementations of this API family support
    /// partially-measured pages or providing a launch token.
    Augusta,
}

use self::DriverFamily::*;

#[derive(Fail, Debug)]
pub enum SgxIoctlError {
    #[fail(display = "I/O ctl failed.")]
    Io(#[cause] IoError),
    #[fail(display = "The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
    #[fail(display = "The enclave was destroyed because the CPU was powered down.")]
    PowerLostEnclave,
    #[fail(display = "Launch enclave version rollback detected.")]
    LeRollback,
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to call ECREATE.")]
    Create(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EADD.")]
    Add(#[cause] SgxIoctlError),
    #[fail(display = "Failed to call EINIT.")]
    Init(#[cause] SgxIoctlError),
    #[fail(display = "Failed to trim region.")]
    Trim(#[cause] SgxIoctlError),
    #[fail(display = "Failed to remove trimmed region.")]
    RemoveTrimmed(#[cause] SgxIoctlError),
    #[fail(display = "Failed to change page type of region.")]
    ChangePageType(#[cause] SgxIoctlError),
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
    type EnclaveController = EnclaveController;
    type Error = Error;

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
                        Map::MAP_SHARED | Map::MAP_ANONYMOUS,
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
            base: ptr as u64,
            size: ecreate.size,
            tcss: vec![],
        };

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
                let flags = match chunks.0 {
                    0 => ioctl::augusta::SgxPageFlags::empty(),
                    0xffff => ioctl::augusta::SgxPageFlags::SGX_PAGE_MEASURE,
                    _ => {
                        return Err(Error::Add(SgxIoctlError::Io(IoError::new(
                            io::ErrorKind::Other,
                            "Partially-measured pages not supported in this driver",
                        ))))
                    }
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
                unsafe {
                    mmap(
                        dstpage as _,
                        4096,
                        prot,
                        Map::MAP_SHARED | Map::MAP_FIXED,
                        mapping.device.fd.as_raw_fd(),
                        0,
                    ).map_err(Error::map)?;
                }

                Ok(())
            }
        }
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        // ioctl() may return ENOTTY if the specified request does not apply to
        // the kind of object that the descriptor fd references.
        fn is_enotty(result: &Result<(), Error>) -> bool {
            match result {
                Err(Error::Init(SgxIoctlError::Io(ref err))) => {
                    err.raw_os_error() == Some(libc::ENOTTY)
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
                    Err(Error::Init(SgxIoctlError::Io(IoError::from_raw_os_error(libc::ENOTTY))))
                }
            }
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
        unsafe { libc::munmap(mapping.base as usize as *mut _, mapping.size as usize) };
    }

    fn create_controller(mapping: &Mapping<Self>) -> Option<Self::EnclaveController> {
        Some(EnclaveController::new(mapping.device.path.clone(), mapping.device.driver))
    }
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
            ("/dev/sgx/enclave", Augusta),
            ("/dev/isgx", Montgomery),
            ("/dev/sgx", Montgomery),
        ];

        for &(path, family) in DEFAULT_DEVICE_PATHS {
            match Self::open(path, family) {
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(ref e) if e.raw_os_error() == Some(libc::ENOTDIR as _) => continue,
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

#[derive(Clone, Debug)]
pub struct EnclaveController{
    path: Arc<PathBuf>,
    family: DriverFamily,
}

impl EnclaveController {
    pub fn new(path: Arc<PathBuf>, family: DriverFamily) -> Self {
        EnclaveController{
            path,
            family,
        }
    }
}

impl EnclaveControl for EnclaveController {
    fn trim(&self, addr: *mut u8, size: usize) -> Result<(), ::failure::Error> {
        match self.family {
            DriverFamily::Augusta => Err(format_err!("Driver doesn't support trimming enclave pages")),
            DriverFamily::Montgomery => {
                let fd = OpenOptions::new().read(true).write(true).open(&**self.path).unwrap();
                let range = SgxRange {
                    start_addr: addr as _,
                    nr_pages: (size / 0x1000) as _,
                };
                let res = ioctl_unsafe!{Trim, ioctl::montgomery::trim(fd.as_raw_fd(), &range)};
                res.map_err(|e| e.into())
            },
        }
    }

    fn remove_trimmed(&self, addr: *const u8, size: usize) -> Result<(), ::failure::Error> {
        match self.family {
            DriverFamily::Augusta => Err(format_err!("Driver doesn't support trimming enclave pages")),
            DriverFamily::Montgomery => {
                let fd = OpenOptions::new().read(true).write(true).open(&**self.path).unwrap();
                let range = SgxRange {
                    start_addr: addr as _,
                    nr_pages: (size / 0x1000) as _,
                };
                let result = ioctl_unsafe!{RemoveTrimmed, ioctl::montgomery::notify_accept(fd.as_raw_fd(), &range)};
                result.map_err(|e| e.into())
            },
        }
    }

    fn change_memory_type(&self, addr: *const u8, size: usize, page_type: PageType) -> Result<(), ::failure::Error> {
        match self.family {
            DriverFamily::Augusta => Err(format_err!("Driver doesn't support changing page types")),
            DriverFamily::Montgomery => {
                let fd = OpenOptions::new().read(true).write(true).open(&**self.path).unwrap();
                let range = SgxRange {
                    start_addr: addr as _,
                    nr_pages: (size / 0x1000) as _,
                    };
                match page_type {
                    PageType::Tcs => {
                        let result = ioctl_unsafe!{ChangePageType, ioctl::montgomery::page_to_tcs(fd.as_raw_fd(), &range)};
                        result.map_err(|e| e.into())
                    }
                    _ => {
                        Err(format_err!("Changing enclave page type to anything other than TCS is not supported"))
                    }
                }
            },
        }
    }
}

impl loader::Load for Device {
    type MappingInfo = MappingInfo<EnclaveController>;
    type Tcs = Tcs;

    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
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
