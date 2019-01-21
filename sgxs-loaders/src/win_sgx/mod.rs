use winapi::um::memoryapi::VirtualFree;
use generic::{self, EinittokenError, EnclaveLoad, Mapping};
use std::io::{Error as IoError, Result as IoResult};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{HANDLE, ENCLAVE_INIT_INFO_SGX, MEM_RELEASE};
use winapi::um::enclaveapi::{CreateEnclave, InitializeEnclave, IsEnclaveTypeSupported, LoadEnclaveData};
use winapi::_core::ffi::c_void;
use abi::{Attributes, Einittoken, Miscselect, PageType, SecinfoFlags, Secs, Sigstruct};
use sgxs_crate::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};
use sgxs_crate::einittoken::EinittokenProvider;
use sgxs_crate::loader;
use std::fs::OpenOptions;

use std::{mem, ptr};
mod defs;
use self::defs::*;
use std::sync::Arc;
use crate::{MappingInfo, Tcs};
use std::path::Path;


pub const DEFAULT_DEVICE_PATH: &'static str = "C:/isgx";

#[derive(Fail, Debug)]
pub enum LibraryError {
    #[fail(
    display = "Enclave type not supported, Intel SGX not supported, or Intel SGX device not present"
    )]
    NotSupported,
    #[fail(display = "SGX - SIGSTRUCT contains an invalid value")]
    InvalidSigstruct,
    #[fail(display = "SGX - invalid signature or the SIGSTRUCT value")]
    InvalidSignature,
    #[fail(display = "SGX - invalid SECS attribute")]
    InvalidAttribute,
    #[fail(display = "SGX - invalid measurement")]
    InvalidMeasurement,
    #[fail(
    display = "Enclave not authorized to run. For example, the enclave does not have a signing privilege required for a requested attribute."
    )]
    NotAuthorized,
    #[fail(display = "Address is not a valid enclave")]
    InvalidEnclave,
    #[fail(display = "SGX - enclave is lost (likely due to a power event)")]
    EnclaveLost,
    #[fail(
    display = "Invalid Parameter (unspecified) - may occur due to a wrong length or format type"
    )]
    InvalidParameter,
    #[fail(
    display = "Out of memory. May be a result of allocation failure in the API or internal function calls"
    )]
    OutOfMemory,
    #[fail(display = "Out of EPC memory")]
    DeviceNoResources,
    #[fail(display = "Enclave has already been initialized")]
    AlreadyInitialized,
    #[fail(display = "Address is not within a valid enclave / Address has already been committed")]
    InvalidAddress,
    #[fail(display = "Please retry the operation - an unmasked event occurred in EINIT")]
    Retry,
    #[fail(display = "Invalid size")]
    InvalidSize,
    #[fail(display = "Enclave is not initialized - the operation requires an initialized enclave")]
    NotInitialized,
    #[fail(display = "Unknown error ({}) in SGX device interface", _0)]
    Other(u32),
    #[fail(display = "OS error ({})", _0)]
    OS(IoError),
}
impl From<u32> for LibraryError {
    fn from(error: u32) -> Self {
        use self::LibraryError::*;
        match error {
            ENCLAVE_NOT_SUPPORTED => NotSupported,
            ENCLAVE_INVALID_SIG_STRUCT => InvalidSigstruct,
            ENCLAVE_INVALID_SIGNATURE => InvalidSignature,
            ENCLAVE_INVALID_ATTRIBUTE => InvalidAttribute,
            ENCLAVE_INVALID_MEASUREMENT => InvalidMeasurement,
            ENCLAVE_NOT_AUTHORIZED => NotAuthorized,
            ENCLAVE_INVALID_ENCLAVE => InvalidEnclave,
            ENCLAVE_LOST => EnclaveLost,
            ENCLAVE_INVALID_PARAMETER => InvalidParameter,
            ENCLAVE_OUT_OF_MEMORY => OutOfMemory,
            ENCLAVE_DEVICE_NO_RESOURCES => DeviceNoResources,
            ENCLAVE_ALREADY_INITIALIZED => AlreadyInitialized,
            ENCLAVE_INVALID_ADDRESS => InvalidAddress,
            ENCLAVE_RETRY => Retry,
            ENCLAVE_INVALID_SIZE => InvalidSize,
            ENCLAVE_NOT_INITIALIZED => NotInitialized,
            _ => Other(error),
        }
    }
}
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to call CreateEnclave.")]
    Create(#[cause] LibraryError),
    #[fail(display = "Failed to call LoadEnclaveData.")]
    Add(#[cause] LibraryError),
    #[fail(display = "Failed to call InitializeEnclave.")]
    Init(#[cause] LibraryError),
}
impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        match self {
            &Error::Init(LibraryError::InvalidAttribute) |
            &Error::Init(LibraryError::InvalidMeasurement) |
            // InvalidEinitToken and InvalidCpusvn get coded this way
            &Error::Init(LibraryError::Other(ENCLAVE_UNEXPECTED)) => true,
            _ => false,
        }
    }
}

impl EnclaveLoad for WinInnerLibrary {
    type Error = Error;

    fn new(
        device: Arc<WinInnerLibrary>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error> {
        let secs = Secs {
            size: ecreate.size,
            ssaframesize: ecreate.ssaframesize,
            miscselect,
            attributes,
            ..Default::default()
        };

        let mut error = 0;
        let curhandle: HANDLE = unsafe {GetCurrentProcess()};
        let issupported = unsafe {IsEnclaveTypeSupported(EnclaveType::Sgx as u32)};
        // set error if issupported is false
        if issupported == 0 {
            return Err(Error::Create(LibraryError::NotSupported));
        }
        let base = unsafe {
            CreateEnclave(
                curhandle,
                ptr::null_mut(),
                ecreate.size as _,
                0,
                EnclaveType::Sgx as u32,
                &secs as *const _ as *const c_void,
                mem::size_of::<Secs>() as u32,
                &mut error as *mut u32
            )
        };
        if base.is_null() {
            Err(Error::Create(error.into()))
        } else {
            Ok(Mapping {
                device,
                tcss: vec![],
                base: base as _,
                size: ecreate.size,
            })
        }
    }
    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error> {

        let (eadd, chunks, data) = page;

        let mut flags = WinPageProperties::empty();
        if eadd
            .secinfo
            .flags
            .intersects(SecinfoFlags::PENDING | SecinfoFlags::MODIFIED | SecinfoFlags::PR)
        {
            return Err(Error::Add(LibraryError::InvalidParameter));
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X) {
            if eadd.secinfo.flags.contains(SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X) {
                flags.insert(WinPageProperties::PAGE_EXECUTE_READWRITE);
            }
            else if eadd.secinfo.flags.contains(SecinfoFlags::R | SecinfoFlags::W) {
                flags.insert(WinPageProperties::PAGE_READWRITE);
            }
            else if eadd.secinfo.flags.contains(SecinfoFlags::X | SecinfoFlags::R) {
                flags.insert(WinPageProperties::PAGE_EXECUTE_READ);
            }
            else if eadd.secinfo.flags.contains(SecinfoFlags::W | SecinfoFlags::X) {
                return Err(Error::Add(LibraryError::InvalidParameter));
            }
            else if eadd.secinfo.flags.contains(SecinfoFlags::R) {
                flags.insert(WinPageProperties::PAGE_READONLY);
            }
            else if eadd.secinfo.flags.contains(SecinfoFlags::X) {
                flags.insert(WinPageProperties::PAGE_EXECUTE);
            }
            else {
                return Err(Error::Add(LibraryError::InvalidParameter));
            }
        }

        match PageType::from_repr(eadd.secinfo.flags.page_type()) {
            Some(PageType::Reg) => {}
            Some(PageType::Tcs) => flags.insert(WinPageProperties::PAGE_TCS),
            _ => return Err(Error::Add(LibraryError::InvalidParameter)),
        }
        match chunks.0 {
            0 => flags.insert(WinPageProperties::PAGE_UNVALIDATED),
            0xffff => {}
            _ => return Err(Error::Add(LibraryError::InvalidParameter)),
        }

        if flags.contains(WinPageProperties::PAGE_TCS) {
            // NOTE: For some reason the windows API needs the Read flag set but then removes it
            assert_eq!(eadd.secinfo.flags.contains(SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X), false);
            flags.insert(WinPageProperties::PAGE_READONLY);
        }
        unsafe {
            let mut error = 0;
            let mut dataLoaded : usize = 0;
            let pDataLoaded: *mut usize = &mut dataLoaded;
            let curhandle: HANDLE = GetCurrentProcess();
            let ret = LoadEnclaveData(
                curhandle,
                (mapping.base + eadd.offset) as _,

                data.as_ptr() as  *const c_void,
                0x1000,
                flags.bits(),
                std::ptr::null(),
                0,
                pDataLoaded,
                &mut error
            ) ;
            if ret == 0 {
                return Err(Error::Add(LibraryError::OS(IoError::last_os_error())));
            }
            assert_eq!(dataLoaded, 0x1000);
        }
        Ok(())
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        let mut initInfo : ENCLAVE_INIT_INFO_SGX = ENCLAVE_INIT_INFO_SGX {
            SigStruct : [0 ; 1808],
            Reserved1 : [0 ; 240],
            EInitToken: [0 ; 304],
            Reserved2 : [0 ; 1744],
        };
        initInfo.SigStruct.clone_from_slice(&sigstruct.as_ref());
        if einittoken.is_some() {
            initInfo.EInitToken.clone_from_slice(&einittoken.unwrap().as_ref());
        }
        unsafe {
            let mut error = 0;

            let curhandle: HANDLE = GetCurrentProcess();
            if InitializeEnclave(
                curhandle,
                mapping.base as _,
                &initInfo as *const _ as *const c_void,
                4096,
                Some(&mut error).unwrap()
            ) == 0 {
                return Err(Error::Init(LibraryError::OS(IoError::last_os_error())));
            }

            Ok(())
        }
    }
    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe {
            // This returns a boolean
            // Need to do error checking using boolean
            if VirtualFree(
                mapping.base  as _,
                0,
                MEM_RELEASE
            ) == 0 {
                panic!("Failed to destroy enclave: {}", IoError::last_os_error())
            }
        }
    }
}

#[derive(Debug)]
struct WinInnerLibrary {}

#[derive(Debug)]
pub struct Device {
    inner: generic::Device<WinInnerLibrary>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<WinInnerLibrary>,
}

impl Device {
    pub fn open() -> IoResult<DeviceBuilder> {
        Ok(DeviceBuilder {
            inner: generic::DeviceBuilder {
                device: generic::Device {
                    inner: Arc::new(WinInnerLibrary {}),
                    einittoken_provider: None,
                },
            },
        })
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
    ) -> ::std::result::Result<loader::Mapping<Self>, ::failure::Error> {
        self.inner
            .load(reader, sigstruct, attributes, miscselect)
            .map(Into::into)
    }
}

impl DeviceBuilder {
    pub fn einittoken_provider<P: Into<Box<EinittokenProvider>>>(
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