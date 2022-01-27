//! The nsm_io library provides an interface to the AWS Nitro Security Module (nsm). Unfortunately,
//! the interface of that crate is not very Rust friendly. To avoid clients of `nsm_io` having to
//! write the same wrapper code over and over again, this crate does this once.
pub use nitro_attestation_verify::{AttestationDocument, Unverified, NitroError as AttestationError, Mbedtls};
use nsm_io::{ErrorCode, Response, Request};
pub use nsm_io::Digest;
pub use serde_bytes::ByteBuf;
use std::collections::BTreeSet;

pub struct Nsm(i32);

#[derive(Debug, PartialEq)]
pub enum Error {
    AttestationError(AttestationError),
    BufferTooSmall,
    CannotOpenDriver,
    InputTooLarge,
    InternalError,
    InvalidArgument,
    InvalidOperation,
    InvalidPcrIndex,
    InvalidResponse,
    ReadOnlyPcrIndex,
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, fmt)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::AttestationError(_e) => "Attestation error",
            Error::BufferTooSmall => "Provided output buffer too small",
            Error::CannotOpenDriver => "Failed to open driver",
            Error::InputTooLarge => "User-provided input is too large",
            Error::InternalError => "NitroSecureModule cannot fulfill request due to internal error",
            Error::InvalidArgument => "Invalid input argument",
            Error::InvalidOperation => "Request cannot be fulfilled due to missing capabilities",
            Error::InvalidPcrIndex => "Platform Configuration Register index out of bounds",
            Error::InvalidResponse => "The received response does not correspond to the earlier request",
            Error::ReadOnlyPcrIndex => "Platform Configuration Register is in read-only mode and the operation attempted to modify it",
        }
    }
}

impl From<AttestationError> for Error {
    fn from(e: AttestationError) -> Self {
        Error::AttestationError(e)
    }
}

impl From<ErrorCode> for Error {
    fn from(e: ErrorCode) -> Self {
        match e {
            ErrorCode::InvalidArgument => Error::InvalidArgument,
            ErrorCode::InvalidIndex => Error::InvalidPcrIndex,
            ErrorCode::InvalidResponse => Error::InvalidResponse,
            ErrorCode::ReadOnlyIndex => Error::ReadOnlyPcrIndex,
            ErrorCode::InvalidOperation => Error::InvalidOperation,
            ErrorCode::BufferTooSmall => Error::BufferTooSmall,
            ErrorCode::InputTooLarge => Error::InputTooLarge,
            ErrorCode::InternalError => Error::InternalError,
            ErrorCode::Success => Error::InvalidResponse,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Pcr {
    locked: bool,
    data: Vec<u8>,
}

impl Pcr {
    fn new(locked: bool, data: Vec<u8>) -> Self {
        Pcr {
            locked,
            data,
        }
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }
}

#[derive(Debug, PartialEq)]
pub struct Description {
    /// Breaking API changes are denoted by `major_version`
    version_major: u16,
    /// Minor API changes are denoted by `minor_version`. Minor versions should be backwards compatible.
    version_minor: u16,
    /// Patch version. These are security and stability updates and do not affect API.
    version_patch: u16,
    /// `module_id` is an identifier for a singular NitroSecureModule
    module_id: String,
    /// The maximum number of PCRs exposed by the NitroSecureModule.
    max_pcrs: u16,
    /// The PCRs that are read-only.
    locked_pcrs: BTreeSet<u16>,
    /// The digest of the PCR Bank
    digest: Digest,
}

impl Description {
    pub fn version_major(&self) -> u16 {
        self.version_major
    }

    /// Minor API changes are denoted by `minor_version`. Minor versions should be backwards compatible.
    pub fn version_minor(&self) -> u16 {
        self.version_minor
    }

    /// Patch version. These are security and stability updates and do not affect API.
    pub fn version_patch(&self) -> u16 {
        self.version_patch
    }

    /// `module_id` is an identifier for a singular NitroSecureModule
    pub fn module_id(&self) -> &String {
        &self.module_id
    }

    /// The maximum number of PCRs exposed by the NitroSecureModule.
    pub fn max_pcrs(&self) -> u16 {
        self.max_pcrs
    }

    /// The PCRs that are read-only.
    pub fn locked_pcrs(&self) -> &BTreeSet<u16> {
        &self.locked_pcrs
    }

    /// The digest of the PCR Bank
    pub fn digest(&self) -> Digest {
        self.digest
    }
}

impl TryFrom<Response> for Description {
    type Error = Error;

    fn try_from(response: Response) -> Result<Self, Self::Error> {
        match response {
            Response::DescribeNSM {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            } => Ok(Description {
                    version_major,
                    version_minor,
                    version_patch,
                    module_id,
                    max_pcrs,
                    locked_pcrs,
                    digest,
                  }),
            Response::Error(code) => Err(code.into()),
            _ => Err(Error::InvalidResponse),
        }
    }
}

impl Nsm {
    pub fn new() -> Result<Self, Error> {
        let fd = nsm_driver::nsm_init();
        if fd < 0 {
            Err(Error::CannotOpenDriver)
        } else {
            Ok(Nsm(fd))
        }
    }

    pub fn attest(&mut self, user_data: Option<ByteBuf>, nonce: Option<ByteBuf>, public_key: Option<ByteBuf>) -> Result<AttestationDocument<Unverified>, Error> {
        let req = Request::Attestation {
            user_data,
            nonce,
            public_key,
        };
        match nsm_driver::nsm_process_request(self.0, req) {
            Response::Attestation { document } => Ok(AttestationDocument::from_slice::<Mbedtls>(document.as_slice())?),
            Response::Error(code) => Err(code.into()),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn describe_pcr(&mut self, idx_pcr: u16) -> Result<Pcr, Error> {
        let req = Request::DescribePCR {
            index: idx_pcr,
        };
        if let Response::DescribePCR { lock, data } = nsm_driver::nsm_process_request(self.0, req) {
            Ok(Pcr::new(lock, data))
        } else {
            Err(Error::InvalidResponse)
        }
    }

    pub fn extend_pcr(&mut self, idx_pcr: u16, data: Vec<u8>) -> Result<Pcr, Error> {
        let req = Request::ExtendPCR {
            index: idx_pcr,
            data,
        };
        if let Response::ExtendPCR { data } = nsm_driver::nsm_process_request(self.0, req) {
            let locked = false; /* Only unlocked PCRs can get extended */
            Ok(Pcr::new(locked, data))
        } else {
            Err(Error::InvalidResponse)
        }
    }

    pub fn lock_pcr(&mut self, idx_pcr: u16) -> Result<(), Error> {
        let req = Request::LockPCR {
            index: idx_pcr,
        };
        match nsm_driver::nsm_process_request(self.0, req) {
            Response::LockPCR     => Ok(()),
            Response::Error(code) => Err(code.into()),
            _                     => Err(Error::InvalidResponse),
        }
    }

    /// Lock PlatformConfigurationRegisters at indexes `[0, range)` from further modifications
    pub fn lock_pcrs(&self, range: u16) -> Result<(), Error> {
        let req = Request::LockPCRs {
            range,
        };
        match nsm_driver::nsm_process_request(self.0, req) {
            Response::LockPCRs    => Ok(()),
            Response::Error(code) => Err(code.into()),
            _                     => Err(Error::InvalidResponse),
        }
    }

    pub fn describe(&self) -> Result<Description, Error> {
        nsm_driver::nsm_process_request(self.0, Request::DescribeNSM).try_into()
    }

    pub fn get_random(&self) -> Result<Vec<u8>, Error> {
        match nsm_driver::nsm_process_request(self.0, Request::GetRandom) {
            Response::GetRandom{ random }    => Ok(random),
            Response::Error(code)            => Err(code.into()),
            _                                => Err(Error::InvalidResponse),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_driver::nsm_exit(self.0);
    }
}
