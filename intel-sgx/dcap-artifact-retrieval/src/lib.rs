//! DCAP attestations require access to Intel-signed artifacts. This library provides clients to
//! access these artifacts both from Intel directly, and from Microsoft Azure.

mod provisioning_client;
pub use provisioning_client::*;

use std::borrow::Cow;
use std::io::Error as IoError;
use std::str::Utf8Error;

#[cfg(feature = "reqwest")]
pub use reqwest::blocking::{Client as ReqwestClient};
use pcs::Error as OAError;
use pkix::ASN1Error;
use quick_error::quick_error;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        PckIdParseError(msg: &'static str) {
            description("Error during parsing PCKID file")
            display("Error parsing PCKID file: {}", msg)
        }
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
        PCSParseError(err: serde_json::error::Error) {
            description("Intel PCS response failed to parse correctly")
            display("json parse error: {}", err)
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
        HeaderParseError(msg : &'static str) {
            description("Header could not be parsed")
            display("Failed to parse header {}", msg)
        }
        CertificateParseError(msg: &'static str) {
            description("Certificate could not be parsed")
            display("Failed to parse certificate {}", msg)
        }
        CertificateEncodingError(err: ASN1Error) {
            from()
        }
        NoEncPPID {
            description("Enc_ppid is required, but not provided")
            display("No enc_ppid was provided")
        }
        NoCPUSVN {
            description("CPU_svn is required, but not provided")
            display("No cpu_svn was provided")
        }
        NoPCEISVSVN {
            description("PCE ISVSVN is required, but not provided")
            display("No pce_isvsvn was provided")
        }
        NoPCEID {
            description("PCEID is required, but not provided")
            display("No pce_id was provided")
        }
        NoQeID {
            description("QEID is required, but not provided")
            display("No QE ID was provided")
        }
        NoAPIKey {
            description("PCS key is required, but not provided")
            display("No api_key was provided")
        }
        OfflineAttestationError(err: OAError) {
            from()
        }
        BadRequest(err: &'static str) {
            description("Bad Request")
            display("{}", err)
        }
        RequestNotSupported {
            description("Client does not support this request")
            display("Client does not support this request")
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "reqwest")]
pub fn reqwest_client() -> ReqwestClient {
    ReqwestClient::builder()
        .use_native_tls()
        .build()
        .expect("Failed to build reqwest client")
}
