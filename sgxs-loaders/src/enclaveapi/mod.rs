use std::convert::TryFrom;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::sync::Arc;
use std::{mem, ptr};

use winapi::ctypes::c_void;
use winapi::um::enclaveapi::{
    CreateEnclave, InitializeEnclave, IsEnclaveTypeSupported, LoadEnclaveData,
};
use winapi::um::memoryapi::VirtualFree;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{
    ENCLAVE_INIT_INFO_SGX, ENCLAVE_TYPE_SGX, MEM_RELEASE, PAGE_ENCLAVE_THREAD_CONTROL,
    PAGE_ENCLAVE_UNVALIDATED, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY, PAGE_READWRITE,
};

use sgx_isa::{Attributes, Einittoken, ErrorCode, Miscselect, PageType, SecinfoFlags, Secs, Sigstruct};
use crate::generic::{self, EinittokenError, EnclaveLoad, Mapping};
use sgxs::einittoken::EinittokenProvider;
use sgxs::loader;
use sgxs::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};

use crate::{MappingInfo, Tcs};

// workaround as winapi doesn't yet have the definition of ERROR_ENCLAVE_FAILURE
// issue no:
const ERROR_ENCLAVE_FAILURE: winapi::shared::minwindef::DWORD = 349;

#[derive(Fail, Debug)]
pub enum EnclaveApiError {
    #[fail(display = "Enclave API failed.")]
    Io(#[cause] IoError),
    #[fail(display = "The SGX instruction returned an error: {:?}.", _0)]
    Ret(ErrorCode),
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Failed to map enclave into memory.")]
    Map(#[cause] IoError),
    #[fail(display = "Failed to call CreateEnclave.")]
    Create(#[cause] IoError),
    #[fail(display = "Failed to call LoadEnclaveData.")]
    Add(#[cause] IoError),
    #[fail(display = "Failed to call InitializeEnclave.")]
    Init(#[cause] EnclaveApiError),
}

impl EinittokenError for Error {
    fn is_einittoken_error(&self) -> bool {
        use self::EnclaveApiError::Ret;
        use self::Error::Init;
        match self {
            &Init(Ret(ErrorCode::InvalidEinitToken)) |
            &Init(Ret(ErrorCode::InvalidCpusvn)) |
            &Init(Ret(ErrorCode::InvalidAttribute)) | // InvalidEinitAttribute according to PR, but does not exist.
            &Init(Ret(ErrorCode::InvalidMeasurement)) => true,
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

        let base = unsafe {
            CreateEnclave(
                GetCurrentProcess(),
                ptr::null_mut(),
                ecreate.size as _,
                0,
                ENCLAVE_TYPE_SGX,
                &secs as *const _ as *const c_void,
                mem::size_of::<Secs>() as _,
                ptr::null_mut(),
            )
        };

        if base.is_null() {
            Err(Error::Create(IoError::last_os_error()))
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

        if eadd
            .secinfo
            .flags
            .intersects(SecinfoFlags::PENDING | SecinfoFlags::MODIFIED | SecinfoFlags::PR)
        {
            return Err(Error::Add(ErrorKind::InvalidInput.into()));
        }
        let mut flags = match (eadd.secinfo.flags
            & (SecinfoFlags::R | SecinfoFlags::W | SecinfoFlags::X))
            .bits()
        {
            0b000 => 0,
            0b001 => PAGE_READONLY,
            0b010 => return Err(Error::Add(ErrorKind::InvalidInput.into())),
            0b011 => PAGE_READWRITE,
            0b100 => PAGE_EXECUTE,
            0b101 => PAGE_EXECUTE_READ,
            0b110 => return Err(Error::Add(ErrorKind::InvalidInput.into())),
            0b111 => PAGE_EXECUTE_READWRITE,
            0b1000..=std::u64::MAX => unreachable!(),
        };
        match PageType::try_from(eadd.secinfo.flags.page_type()) {
            Ok(PageType::Reg) => {}
            Ok(PageType::Tcs) => {
                // NOTE: For some reason the windows API needs the PAGE_READWRITE set
                // but the sgx EADD instruction removes it
                flags = PAGE_ENCLAVE_THREAD_CONTROL | PAGE_READWRITE;
            }
            _ => return Err(Error::Add(ErrorKind::InvalidInput.into())),
        }
        match chunks.0 {
            0 => flags |= PAGE_ENCLAVE_UNVALIDATED,
            0xffff => {}
            _ => {
                return Err(Error::Add(IoError::new(
                    ErrorKind::Other,
                    "Partially-measured pages not supported on Windows",
                )))
            }
        }
        unsafe {
            let mut data_loaded: usize = 0;
            let ret = LoadEnclaveData(
                GetCurrentProcess(),
                (mapping.base + eadd.offset) as _,
                data.as_ptr() as *const c_void,
                data.len(),
                flags,
                ptr::null(),
                0,
                &mut data_loaded,
                ptr::null_mut(),
            );
            if ret == winapi::shared::minwindef::FALSE {
                return Err(Error::Add(IoError::last_os_error()));
            }
            assert_eq!(data_loaded, data.len());
        }
        Ok(())
    }

    fn init(
        mapping: &Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        let mut init_info: ENCLAVE_INIT_INFO_SGX = ENCLAVE_INIT_INFO_SGX {
            SigStruct: [0; 1808],
            Reserved1: [0; 240],
            EInitToken: [0; 304],
            Reserved2: [0; 1744],
        };
        init_info.SigStruct.copy_from_slice(&sigstruct.as_ref());
        if let Some(e) = einittoken {
            init_info.EInitToken.copy_from_slice(e.as_ref());
        }
        unsafe {
            let mut error = 0;
            if InitializeEnclave(
                GetCurrentProcess(),
                mapping.base as _,
                &init_info as *const _ as *const c_void,
                mem::size_of::<ENCLAVE_INIT_INFO_SGX>() as _,
                &mut error,
            ) == winapi::shared::minwindef::FALSE
            {
                if IoError::last_os_error().raw_os_error() == Some(ERROR_ENCLAVE_FAILURE as i32) {
                    if let Ok(e) = ErrorCode::try_from(error) {
                        return Err(Error::Init(EnclaveApiError::Ret(e)));
                    }
                }
            }

            Ok(())
        }
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe {
            // This returns a boolean
            // Need to do error checking using boolean
            if VirtualFree(mapping.base as _, 0, MEM_RELEASE) == winapi::shared::minwindef::FALSE {
                panic!("Failed to destroy enclave: {}", IoError::last_os_error())
            }
        }
    }
}

#[derive(Debug)]
struct WinInnerLibrary {}

#[derive(Debug)]
pub struct Sgx {
    inner: generic::Device<WinInnerLibrary>,
}

pub struct DeviceBuilder {
    inner: generic::DeviceBuilder<WinInnerLibrary>,
}

impl Sgx {
    pub fn new() -> IoResult<DeviceBuilder> {
        let issupported = unsafe { IsEnclaveTypeSupported(ENCLAVE_TYPE_SGX) };
        if issupported == winapi::shared::minwindef::FALSE {
            return Err(IoError::last_os_error());
        }

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

impl loader::Load for Sgx {
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
    pub fn einittoken_provider<P: Into<Box<dyn EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Sgx {
        Sgx {
            inner: self.inner.build(),
        }
    }
}
