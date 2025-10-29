/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub extern crate libloading as dl;

use std::convert::TryFrom;
use std::io::{Result as IoResult, Error as IoError};
use std::os::raw::c_void;
use std::sync::Arc;
use std::{fmt, mem, ptr};

use sgx_isa::{Attributes, Einittoken, Miscselect, PageType, SecinfoFlags, Secs, Sigstruct};
use sgxs::einittoken::EinittokenProvider;
use sgxs::loader;
use sgxs::sgxs::{MeasEAdd, MeasECreate, PageChunks, SgxsRead};
use thiserror::Error as ThisError;

use crate::{MappingInfo, Tcs};
use crate::generic::{self, EinittokenError, EnclaveLoad, Mapping};

mod defs;

use self::defs::*;

#[derive(ThisError, Debug)]
#[non_exhaustive]
pub enum LibraryError {
    #[error(
        "Enclave type not supported, Intel SGX not supported, or Intel SGX device not present"
    )]
    NotSupported,
    #[error("SGX - SIGSTRUCT contains an invalid value")]
    InvalidSigstruct,
    #[error("SGX - invalid signature or the SIGSTRUCT value")]
    InvalidSignature,
    #[error("SGX - invalid SECS attribute")]
    InvalidAttribute,
    #[error("SGX - invalid measurement")]
    InvalidMeasurement,
    #[error(
        "Enclave not authorized to run. For example, the enclave does not have a signing privilege required for a requested attribute."
    )]
    NotAuthorized,
    #[error("Address is not a valid enclave")]
    InvalidEnclave,
    #[error("SGX - enclave is lost (likely due to a power event)")]
    EnclaveLost,
    #[error(
        "Invalid Parameter (unspecified) - may occur due to a wrong length or format type"
    )]
    InvalidParameter,
    #[error(
        "Out of memory. May be a result of allocation failure in the API or internal function calls"
    )]
    OutOfMemory,
    #[error("Out of EPC memory")]
    DeviceNoResources,
    #[error("Enclave has already been initialized")]
    AlreadyInitialized,
    #[error("Address is not within a valid enclave / Address has already been committed")]
    InvalidAddress,
    #[error("Please retry the operation - an unmasked event occurred in EINIT")]
    Retry,
    #[error("Invalid size")]
    InvalidSize,
    #[error("Enclave is not initialized - the operation requires an initialized enclave")]
    NotInitialized,
    #[error("Unexpected error in the API")]
    Unexpected,
    #[error("Unknown error ({}) in SGX device interface", _0)]
    Other(u32),
    #[error("Failed to adjust the page table permissions: {}", _0)]
    PageTableFailure(IoError),
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
            ENCLAVE_UNEXPECTED => Unexpected,
            _ => Other(error),
        }
    }
}

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to call ECREATE.")]
    Create(#[source] LibraryError),
    #[error("Failed to call EADD.")]
    Add(#[source] LibraryError),
    #[error("Failed to call EINIT.")]
    Init(#[source] LibraryError),
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

impl EnclaveLoad for InnerLibrary {
    type Error = Error;
    type MapData = ();

    fn new(
        device: Arc<InnerLibrary>,
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

        let base = unsafe {
            (device.enclave_create)(
                ptr::null_mut(),
                ecreate.size as _,
                0,
                EnclaveType::Sgx1,
                &secs,
                mem::size_of::<Secs>(),
                Some(&mut error),
            )
        };

        if base.is_null() {
            Err(Error::Create(error.into()))
        } else {
            Ok(Mapping {
                device,
                mapdata: (),
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
        let data = Align4096(data);

        let mut flags = PageProperties::empty();
        if eadd
            .secinfo
            .flags
            .intersects(SecinfoFlags::PENDING | SecinfoFlags::MODIFIED | SecinfoFlags::PR)
        {
            return Err(Error::Add(LibraryError::InvalidParameter));
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::R) {
            flags.insert(PageProperties::R)
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::W) {
            flags.insert(PageProperties::W)
        }
        if eadd.secinfo.flags.intersects(SecinfoFlags::X) {
            flags.insert(PageProperties::X)
        }
        match PageType::try_from(eadd.secinfo.flags.page_type()) {
            Ok(PageType::Reg) => {}
            Ok(PageType::Tcs) => flags.insert(PageProperties::TCS),
            _ => return Err(Error::Add(LibraryError::InvalidParameter)),
        }
        match chunks.0 {
            0 => flags.insert(PageProperties::UNVALIDATED),
            0xffff => {}
            _ => return Err(Error::Add(LibraryError::InvalidParameter)),
        }

        unsafe {
            let mut error = 0;
            if (mapping.device.enclave_load_data)(
                (mapping.base + eadd.offset) as _,
                0x1000,
                &data,
                flags,
                Some(&mut error),
            ) != 0x1000
            {
                return Err(Error::Add(error.into()));
            }
        }

        Ok(())
    }

    fn init(
        mapping: &mut Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error> {
        unsafe {
            let mut error = 0;

            if let Some(einittoken) = einittoken {
                if !(mapping.device.enclave_set_information)(
                    mapping.base as _,
                    InfoType::EnclaveLaunchToken,
                    einittoken as *const _ as _,
                    mem::size_of::<Einittoken>(),
                    Some(&mut error),
                ) {
                    match Error::Init(error.into()) {
                        // ignore error if setting einittoken is not supported
                        Error::Init(LibraryError::NotSupported) => {}
                        err => return Err(err),
                    }
                }
            }

            if !(mapping.device.enclave_initialize)(
                mapping.base as _,
                sigstruct,
                Sigstruct::UNPADDED_SIZE,
                Some(&mut error),
            ) {
                return Err(Error::Init(error.into()));
            }

            Ok(())
        }
    }

    fn destroy(mapping: &mut Mapping<Self>) {
        unsafe {
            (mapping.device.enclave_delete)(mapping.base as _, None);
        }
    }
}

struct InnerLibrary {
    library: dl::Library,
    enclave_create: EnclaveCreateFn,
    enclave_load_data: EnclaveLoadDataFn,
    enclave_initialize: EnclaveInitializeFn,
    enclave_delete: EnclaveDeleteFn,
    enclave_set_information: EnclaveSetInformationFn,
}

impl fmt::Debug for InnerLibrary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InnerLibrary")
            .field("library", &self.library)
            .field("enclave_create", &(self.enclave_create as *const c_void))
            .field(
                "enclave_load_data",
                &(self.enclave_load_data as *const c_void),
            )
            .field(
                "enclave_initialize",
                &(self.enclave_initialize as *const c_void),
            )
            .field("enclave_delete", &(self.enclave_delete as *const c_void))
            .field(
                "enclave_set_information",
                &(self.enclave_set_information as *const c_void),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct Library {
    inner: generic::Device<InnerLibrary>,
}

pub struct LibraryBuilder {
    inner: generic::DeviceBuilder<InnerLibrary>,
}

impl Library {
    pub fn load(library: Option<dl::Library>) -> IoResult<LibraryBuilder> {
        unsafe {
            let library = library.map_or_else(|| dl::Library::new(LIBRARY), Ok)?;
            let enclave_create = *library.get::<EnclaveCreateFn>(SYM_ENCLAVE_CREATE)?;
            let enclave_load_data = *library.get::<EnclaveLoadDataFn>(SYM_ENCLAVE_LOAD_DATA)?;
            let enclave_initialize = *library.get::<EnclaveInitializeFn>(SYM_ENCLAVE_INITIALIZE)?;
            let enclave_delete = *library.get::<EnclaveDeleteFn>(SYM_ENCLAVE_DELETE)?;
            let enclave_set_information =
                *library.get::<EnclaveSetInformationFn>(SYM_ENCLAVE_SET_INFORMATION)?;
            Ok(LibraryBuilder {
                inner: generic::DeviceBuilder {
                    device: generic::Device {
                        inner: Arc::new(InnerLibrary {
                            library,
                            enclave_create,
                            enclave_load_data,
                            enclave_initialize,
                            enclave_delete,
                            enclave_set_information,
                        }),
                        einittoken_provider: None,
                    },
                },
            })
        }
    }
}

impl loader::Load for Library {
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

impl LibraryBuilder {
    pub fn einittoken_provider<P: Into<Box<dyn EinittokenProvider>>>(
        mut self,
        einittoken_provider: P,
    ) -> Self {
        self.inner.einittoken_provider(einittoken_provider.into());
        self
    }

    pub fn build(self) -> Library {
        Library {
            inner: self.inner.build(),
        }
    }
}
