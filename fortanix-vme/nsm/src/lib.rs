pub use nitro_attestation_verify::{AttestationDocument, Unverified, NitroError as AttestationError};
use nsm_io::{ErrorCode, Response, Request};
pub use serde_bytes::ByteBuf;

pub struct Nsm(i32);

#[derive(Debug)]
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
        match self {
            Error::AttestationError(ref msg) => write!(fmt, "Attestation error: {}", msg),
            Error::BufferTooSmall => write!(fmt, "Buffer too small"),
            Error::CannotOpenDriver => write!(fmt, "CannotOpenDriver"),
            Error::InputTooLarge => write!(fmt, "InputTooLarge"),
            Error::InternalError => write!(fmt, "InternalError"),
            Error::InvalidArgument => write!(fmt, "InvalidArgument"),
            Error::InvalidOperation => write!(fmt, "InvalidOperation"),
            Error::InvalidPcrIndex => write!(fmt, "InvalidPcrIndex"),
            Error::InvalidResponse => write!(fmt, "InvalidResponse"),
            Error::ReadOnlyPcrIndex => write!(fmt, "ReadOnlyPcrIndex"),
        }
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
            Response::Attestation { document } => Ok(AttestationDocument::from_slice(document.as_slice())?),
            Response::Error(code) => Err(code.into()),
            _ => Err(Error::InvalidResponse),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_driver::nsm_exit(self.0);
    }
}
