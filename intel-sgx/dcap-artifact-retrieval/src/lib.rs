/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! DCAP attestations require access to Intel-signed artifacts. This library provides clients to
//! access these artifacts both from Intel directly, and from Microsoft Azure.

#[cfg(all(not(target_env = "sgx"), feature = "reqwest"))]
pub mod cli;
pub mod provisioning_client;

pub use self::provisioning_client::*;

use std::borrow::Cow;
use std::io::Error as IoError;
use std::str::Utf8Error;

use pcs::Error as OAError;
use pkix::ASN1Error;
use quick_error::quick_error;
#[cfg(feature = "reqwest")]
pub use reqwest::blocking::Client as ReqwestClient;

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

/// Create a reqwest client using native tls(by default) or rustls if feature
/// "rustls-tls" is enabled.
#[cfg(feature = "reqwest")]
pub fn reqwest_client() -> ReqwestClient {
    #[cfg(not(feature = "rustls-tls"))]
    {
        reqwest_client_native_tls()
    }
    #[cfg(feature = "rustls-tls")]
    {
        reqwest_client_rustls()
    }
}

/// Create a reqwest client using rustls tls.
#[cfg(all(feature = "reqwest", feature = "rustls-tls"))]
pub fn reqwest_client_rustls() -> ReqwestClient {
    ReqwestClient::builder()
        .use_rustls_tls()
        .build()
        .expect("Failed to build reqwest client")
}

/// Create a reqwest client using native tls.
#[cfg(all(feature = "reqwest"))]
pub fn reqwest_client_native_tls() -> ReqwestClient {
    ReqwestClient::builder()
        .use_native_tls()
        .build()
        .expect("Failed to build reqwest client")
}

#[cfg(feature = "reqwest")]
#[doc(hidden)]
pub fn reqwest_client_insecure_tls() -> ReqwestClient {
    let client_builder;
    #[cfg(not(feature = "rustls-tls"))]
    {
        client_builder = ReqwestClient::builder().use_native_tls();
    }
    #[cfg(feature = "rustls-tls")]
    {
        client_builder = ReqwestClient::builder().use_rustls_tls();
    }
    client_builder
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to build reqwest client")
}
