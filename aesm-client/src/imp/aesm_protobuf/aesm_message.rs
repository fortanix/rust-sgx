pub use error::{Error, Result};
use protobuf::ProtobufResult;
use aesm_proto::*;

// From SDK aesm_error.h
const AESM_SUCCESS: u32 = 0;

pub(crate) trait AesmRequest: protobuf::Message + Into<Request> {
    type Response: protobuf::Message + FromResponse;

    fn get_timeout(&self) -> Option<u32>;
}

// This could be replaced with TryFrom when stable.
pub(crate) trait FromResponse: Sized {
    fn from_response(res: ProtobufResult<Response>) -> Result<Self>;
}

macro_rules! define_aesm_message {
    ($request:ident, $response:ident, $set:ident, $has:ident, $take:ident) => {
        impl AesmRequest for $request {
            type Response = $response;

            fn get_timeout(&self) -> Option<u32> {
                if self.has_timeout() {
                    Some(Self::get_timeout(self))
                } else {
                    None
                }
            }
        }
        impl From<$request> for Request {
            fn from(r: $request) -> Request {
                let mut req = Request::new();
                req.$set(r);
                req
            }
        }
        impl FromResponse for $response {
            fn from_response(mut res: ProtobufResult<Response>) -> Result<Self> {
                match res {
                    Ok(ref mut res) if res.$has() => {
                        let body = res.$take();
                        match body.get_errorCode() {
                            AESM_SUCCESS => Ok(body),
                            code => Err(Error::aesm_code(code)),
                        }
                    }
                    _ => Err(Error::aesm_bad_response(stringify!($response))),
                }
            }
        }
    }
}

define_aesm_message!(Request_GetQuoteRequest,    Response_GetQuoteResponse,    set_getQuoteReq,    has_getQuoteRes,    take_getQuoteRes);
define_aesm_message!(Request_InitQuoteRequest,   Response_InitQuoteResponse,   set_initQuoteReq,   has_initQuoteRes,   take_initQuoteRes);
define_aesm_message!(Request_GetLaunchTokenRequest, Response_GetLaunchTokenResponse, set_getLicTokenReq, has_getLicTokenRes, take_getLicTokenRes);
define_aesm_message!(Request_GetQuoteExRequest,  Response_GetQuoteExResponse,  set_getQuoteExReq,  has_getQuoteExRes,  take_getQuoteExRes);
define_aesm_message!(Request_InitQuoteExRequest, Response_InitQuoteExResponse, set_initQuoteExReq, has_initQuoteExRes, take_initQuoteExRes);
define_aesm_message!(Request_GetQuoteSizeExRequest, Response_GetQuoteSizeExResponse,  set_getQuoteSizeExReq, has_getQuoteSizeExRes, take_getQuoteSizeExRes);
define_aesm_message!(Request_GetSupportedAttKeyIDNumRequest, Response_GetSupportedAttKeyIDNumResponse, set_getSupportedAttKeyIDNumReq, has_getSupportedAttKeyIDNumRes, take_getSupportedAttKeyIDNumRes);
define_aesm_message!(Request_GetSupportedAttKeyIDsRequest,   Response_GetSupportedAttKeyIDsResponse,   set_getSupportedAttKeyIDsReq,   has_getSupportedAttKeyIDsRes,   take_getSupportedAttKeyIDsRes);
