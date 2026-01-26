use fortanix_vme_initramfs::Error as InitramfsError;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Initramfs error")]
    InitramfsError(#[from] InitramfsError),
    #[error("Writing kernel to file failed")]
    KernelWriteError(#[source] io::Error),
    #[error("Writing kernel config to file failed")]
    KernelConfigWriteError(#[source] io::Error),
    #[error("Generating Eif info failed: {error}")]
    EifIdentityInfoError { error: String },
    #[error("Writing Eif failed")]
    EifWriteError(#[source] io::Error),
    #[error("Reading Eif failed")]
    EifReadError(#[source] io::Error),
    #[error("Parsing Eif failed")]
    EifParseError(String),
    #[error("Parsing Metadata section failed")]
    MetadataParseError(#[source] serde_json::Error),
}

impl Error {
    pub fn eif_identity_info(error: String) -> Self {
        Error::EifIdentityInfoError { error }
    }
}
