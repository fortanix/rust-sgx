//! DCAP attestations require access to Intel-signed artifacts. This library provides clients to
//! access these artifacts both from Intel directly, and from Microsoft Azure.

mod provisioning_client;
pub use provisioning_client::*;

use std::borrow::Cow;
use std::io::Error as IoError;
use std::str::Utf8Error;

#[cfg(feature = "reqwest")]
use reqwest::blocking::{Client as ReqwestClient};
use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        ReadResponseError(msg: Cow<'static, str>) {
            from()
            display("{}", msg)
        }
        FetcherFailure(err: String) {
            from()
            display("{}", err)
        }
        IoError(err: IoError) {
            from()
        }
        PCSError(status_code: StatusCode, msg : &'static str ) {
            description("Certification services returned an unexpected response")
            display("{}", msg)
        }
        PCSDecodeError(error: Cow<'static, str>) {
            description("Intel PCS response could not be decoded")
            display("percent decoding failed: {}", error)
        }
        HeaderMissing(msg : &'static str) {
            description("Expected header was not present")
            display("Expected header \"{}\" missing", msg)
        }
        HeaderDecodeError(err : Utf8Error) {
            description("Intel certification services returned a header that could not be decoded")
            display("Failed to decode header")
        }
        CertificateParseError(msg: &'static str) {
            description("Certificate could not be parsed")
            display("Failed to parse certificate {}", msg)
        }
        NoEncPPID {
            description("Enc_ppid is required, but not provided")
            display("No enc_ppid was provided")
        }
        NoQeID {
            description("QEID is required, but not provided")
            display("No QE ID was provided")
        }
        PCSProvisioningError(err: pcs::Error) {
            from()
        }
        RequestNotSupported {
            description("Client does not support this request")
            display("Client does not support this request")
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn reqwest_client() -> ReqwestClient {
    ReqwestClient::builder()
        .use_native_tls()
        .build()
        .expect("Failed to build reqwest client")
}
