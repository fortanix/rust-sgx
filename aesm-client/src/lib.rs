/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! # Features
//!
//! * `sgxs`. Enable the `sgxs` feature to get an implemention of
//!   `EinittokenProvider` that uses AESM.

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]
#![deny(warnings)]

extern crate byteorder;
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
#[cfg(unix)]
extern crate lazy_static;
extern crate protobuf;
#[cfg(feature = "sgxs")]
extern crate sgxs;
#[cfg(unix)]
extern crate unix_socket;
#[cfg(windows)]
extern crate winapi;
extern crate sgx_isa;

#[cfg(feature = "sgxs")]
use std::result::Result as StdResult;

use protobuf::ProtobufResult;
#[cfg(feature = "sgxs")]
use sgxs::einittoken::{Einittoken, EinittokenProvider};
use sgx_isa::{Attributes, Sigstruct};

include!(concat!(env!("OUT_DIR"), "/mod_aesm_proto.rs"));
mod error;
use self::aesm_proto::*;
pub use error::{AesmError, Error, Result};
#[cfg(windows)]
#[path = "imp/windows.rs"]
mod imp;
#[cfg(unix)]
#[path = "imp/unix.rs"]
mod imp;
#[cfg(unix)]
pub mod unix {
    use std::path::Path;
    pub trait AesmClientExt {
        fn with_path<P: AsRef<Path>>(path: P) -> Self;
    }
}

// From SDK aesm_error.h
const AESM_SUCCESS: u32 = 0;

// From SDK sgx_quote.h
#[repr(u32)]
pub enum QuoteType {
    Unlinkable = 0,
    Linkable = 1,
}

impl Into<u32> for QuoteType {
    fn into(self: QuoteType) -> u32 {
        use self::QuoteType::*;
        match self {
            Unlinkable => 0,
            Linkable => 1,
        }
    }
}

impl QuoteType {
    pub fn from_u32(v: u32) -> Result<Self> {
        use self::QuoteType::*;
        Ok(match v {
            0 => Unlinkable,
            1 => Linkable,
            _ => return Err(Error::InvalidQuoteType(v)),
        })
    }
}

#[derive(Debug)]
pub struct QuoteInfo {
    target_info: Vec<u8>,

    /// EPID group ID, big-endian byte order
    gid: Vec<u8>,
}

impl QuoteInfo {
    pub fn target_info(&self) -> &[u8] {
        &self.target_info
    }

    pub fn gid(&self) -> &[u8] {
        &self.gid
    }

    // The value returned here can depend on number of sigrl entries, and
    // possibly other factors. Although why the client needs to pass a length
    // in a protobuf API is beyond me.
    fn quote_buffer_size(&self, sig_rl: &[u8]) -> u32 {
        // Refer to se_quote_internal.h and sgx_quote.h in the Intel SDK.
        let quote_length = 436 + 288 + 12 + 4 + 16;

        // Refer to epid/common/types.h in the Intel SDK.
        // This is the truly correct way to compute sig_length:
        //let nr_proof_length = 160;
        //let sig_length = 352 + 4 + 4 + sig_rl_entries * nr_proof_length;
        // Instead we do something that should be conservative, and doesn't
        // require interpreting the sig_rl structure to determine the entry
        // count. An nr_proof is 5 field elements, a sig_rl entry is four.
        // Add some slop for sig_rl headers.
        let sig_length = 352 + 4 + 4 + (sig_rl.len() as u32 * 5 / 4) + 128;

        quote_length + sig_length
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuoteResult {
    /// For Intel attestatations, the EPID signature from Intel QE.
    quote: Vec<u8>,

    /// SGX report (EREPORT) from the Intel quoting enclave for the quote.
    qe_report: Vec<u8>,
}

impl QuoteResult {
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(quote: T, qe_report: U) -> Self {
        QuoteResult {
            quote: quote.into(),
            qe_report: qe_report.into(),
        }
    }

    pub fn quote(&self) -> &[u8] {
        &self.quote
    }

    pub fn qe_report(&self) -> &[u8] {
        &self.qe_report
    }
}

#[derive(Default, Debug, Clone)]
pub struct AesmClient {
    inner: imp::AesmClient
}

impl AesmClient {
    pub fn new() -> Self {
        AesmClient { inner: imp::AesmClient::new() }
    }

    /// Test the connection with AESM.
    ///
    /// This should only be used for diagnostic purposes. This method returning
    /// `Ok` is not a guarantee that any of the other methods will function
    /// correctly.
    pub fn try_connect(&self) -> Result<()> {
        self.inner.try_connect()
    }

    pub fn init_quote(&self) -> Result<QuoteInfo> {
        self.inner.init_quote()
    }

    pub fn get_quote(
        &self,
        session: &QuoteInfo,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> Result<QuoteResult> {
        self.inner.get_quote(
            session,
            report,
            spid,
            sig_rl,
        )
    }

    pub fn get_launch_token(
        &self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
    ) -> Result<Vec<u8>> {
        self.inner.get_launch_token(
            sigstruct,
            attributes,
        )
    }
}

#[cfg(feature = "sgxs")]
impl EinittokenProvider for AesmClient {
    fn token(
        &mut self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        _retry: bool,
    ) -> StdResult<Einittoken, ::failure::Error> {
        let token = self.get_launch_token(
            sigstruct,
            attributes,
        )?;
        Einittoken::try_copy_from(&token).ok_or(Error::InvalidTokenSize.into())
    }

    fn can_retry(&self) -> bool {
        false
    }
}

trait AesmRequest: protobuf::Message + Into<Request> {
    type Response: protobuf::Message + FromResponse;

    fn get_timeout(&self) -> Option<u32>;
}

// This could be replaced with TryFrom when stable.
trait FromResponse: Sized {
    fn from_response(res: ProtobufResult<Response>) -> Result<Self>;
}

impl AesmRequest for Request_InitQuoteRequest {
    type Response = Response_InitQuoteResponse;

    fn get_timeout(&self) -> Option<u32> {
        if self.has_timeout() {
            Some(Self::get_timeout(self))
        } else {
            None
        }
    }
}

impl From<Request_InitQuoteRequest> for Request {
    fn from(r: Request_InitQuoteRequest) -> Request {
        let mut req = Request::new();
        req.set_initQuoteReq(r);
        req
    }
}

impl FromResponse for Response_InitQuoteResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_initQuoteRes() => {
                let body = res.take_initQuoteRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("InitQuoteResponse")),
        }
    }
}

impl AesmRequest for Request_GetQuoteRequest {
    type Response = Response_GetQuoteResponse;

    fn get_timeout(&self) -> Option<u32> {
        if self.has_timeout() {
            Some(Self::get_timeout(self))
        } else {
            None
        }
    }
}

impl From<Request_GetQuoteRequest> for Request {
    fn from(r: Request_GetQuoteRequest) -> Request {
        let mut req = Request::new();
        req.set_getQuoteReq(r);
        req
    }
}

impl FromResponse for Response_GetQuoteResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_getQuoteRes() => {
                let body = res.take_getQuoteRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("GetQuoteResponse")),
        }
    }
}

impl AesmRequest for Request_GetLaunchTokenRequest {
    type Response = Response_GetLaunchTokenResponse;

    fn get_timeout(&self) -> Option<u32> {
        if self.has_timeout() {
            Some(Self::get_timeout(self))
        } else {
            None
        }
    }
}

impl From<Request_GetLaunchTokenRequest> for Request {
    fn from(r: Request_GetLaunchTokenRequest) -> Request {
        let mut req = Request::new();
        req.set_getLicTokenReq(r);
        req
    }
}

impl FromResponse for Response_GetLaunchTokenResponse {
    fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
        match res {
            Ok(ref mut res) if res.has_getLicTokenRes() => {
                let body = res.take_getLicTokenRes();
                match body.get_errorCode() {
                    AESM_SUCCESS => Ok(body),
                    code => Err(Error::aesm_code(code)),
                }
            }
            _ => Err(Error::aesm_bad_response("GetLaunchTokenResponse")),
        }
    }
}

#[cfg(all(test, feature = "test-sgx"))]
mod tests {
    // These tests require that aesmd is running and correctly configured.
    extern crate sgx_isa;

    use self::sgx_isa::{Report, Targetinfo};
    use super::*;

    const SPID_SIZE: usize = 16;

    #[test]
    fn test_init_quote() {
        let quote = AesmClient::new().init_quote().unwrap();
        assert_eq!(
            quote.target_info().len(),
            ::std::mem::size_of::<Targetinfo>()
        );
        assert!(quote.gid().len() != 0);
    }

    #[test]
    fn test_get_quote() {
        // Doing a meaningful test of this requires creating an enclave, this is
        // just a simple test that we can send a bogus request and get an error
        // back. The node attest flow in testsetup.sh exercises the real case.
        let client = AesmClient::new();

        let quote = client.init_quote().unwrap();

        let quote = client
            .get_quote(
                &quote,
                vec![0u8; Report::UNPADDED_SIZE],
                vec![0u8; SPID_SIZE],
                vec![],
            )
            .unwrap_err();

        assert!(if let Error::AesmCode(_) = quote {
            true
        } else {
            false
        });
    }
}
