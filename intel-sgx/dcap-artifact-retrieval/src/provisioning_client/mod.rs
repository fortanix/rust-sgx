/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::convert::TryFrom;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use lru_cache::LruCache;
use num_enum::TryFromPrimitive;
use pcs::{
    CpuSvn, DcapArtifactIssuer, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl, PckID, PlatformTypeForTcbInfo, QeId, QeIdentitySigned, RawTcbEvaluationDataNumbers, TcbInfo, Unverified, platform
};
#[cfg(feature = "reqwest")]
use reqwest::blocking::{Client as ReqwestClient, Response as ReqwestResponse};
use rustc_serialize::hex::ToHex;

use crate::Error;
use crate::provisioning_client::common::{ENCLAVE_ID_ISSUER_CHAIN_HEADER, PCK_CERTIFICATE_ISSUER_CHAIN_HEADER, PCK_CRL_ISSUER_CHAIN_HEADER, TCB_EVALUATION_DATA_NUMBERS_ISSUER_CHAIN, TCB_INFO_ISSUER_CHAIN_HEADER_V3, TCB_INFO_ISSUER_CHAIN_HEADER_V4, parse_issuer_header};

pub mod azure;
pub(self) mod common;
pub mod intel;
pub mod pccs;

pub use self::azure::AzureProvisioningClientBuilder;
pub use self::intel::IntelProvisioningClientBuilder;
pub use self::pccs::PccsProvisioningClientBuilder;

// Taken from https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
#[derive(Clone, Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u16)]
pub enum StatusCode {
    Continue = 100,
    SwitchingProtocols = 101,
    Processing = 102,
    EarlyHints = 103,
    //104-199	Unassigned
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    //209-225	Unassigned
    ImUsed = 226,
    //227-299	Unassigned
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    #[num_enum(alternatives = [418])]
    Unused = 306,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    // 309-399	Unassigned
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    ContentTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    //418 Unused
    //419-420	Unassigned,
    MisdirectedRequest = 421,
    UnprocessableContent = 422,
    Locked = 423,
    FailedDependency = 424,
    TooEarly = 425,
    UpgradeRequired = 426,
    // 427 Unassigned
    PreconditionRequired = 428,
    TooManyRequests = 429,
    //430 Unassigned
    RequestHeaderFieldsTooLarge = 431,
    //432-450	Unassigned,
    UnavailableForLegalReasons = 451,
    //452-460	Unassigned,
    NonStandard461 = 461, // used by PCCS
    NonStandard462 = 462, // used by PCCS
    //463-499	Unassigned,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    //509 Unassigned
    NotExtended = 510, // OBSOLETED
    NetworkAuthenticationRequired = 511,
    //512-599	Unassigned
    #[num_enum(alternatives = [104..=199, 209..=225, 227..=299, 309..=399, 419, 420, 427, 430, 432..=450, 452..=460, 463..=499, 509, 512..=598])]
    Unassigned = 599,
}

const SUBSCRIPTION_KEY_HEADER: &'static str = "Ocp-Apim-Subscription-Key";

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum PcsVersion {
    V3 = 3,
    V4 = 4,
}

pub trait WithApiVersion {
    fn api_version(&self) -> PcsVersion;
}

impl WithApiVersion for PcsVersion {
    fn api_version(&self) -> PcsVersion {
        *self
    }
}

trait PlatformApiTag {
    fn tag() -> &'static str;
}

impl PlatformApiTag for platform::SGX {
    fn tag() -> &'static str {
        "sgx"
    }
}

impl PlatformApiTag for platform::TDX {
    fn tag() -> &'static str {
        "tdx"
    }
}

#[derive(Hash)]
pub struct PckCertsIn<'a> {
    enc_ppid: &'a EncPpid,
    pce_id: PceId,
    api_key: &'a Option<String>,
    api_version: PcsVersion,
}

impl WithApiVersion for PckCertsIn<'_> {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}



#[derive(Hash)]
pub struct PckCertIn<'a> {
    encrypted_ppid: Option<&'a EncPpid>,
    pce_id: &'a PceId,
    cpu_svn: &'a CpuSvn,
    pce_isvsvn: PceIsvsvn,
    qe_id: Option<&'a QeId>,
    api_version: PcsVersion,
    api_key: &'a Option<String>,
}

impl WithApiVersion for PckCertIn<'_> {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}
struct PckCertService;
impl ProvisioningServiceApi for PckCertService {
    type Input<'a> = PckCertIn<'a>;
    type Output = PckCert<Unverified>;

    fn build_request(base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input
            .encrypted_ppid
            .ok_or(Error::NoEncPPID)
            .map(|e_ppid| e_ppid.to_hex())?;
        let cpusvn = input.cpu_svn.to_hex();
        let pce_isvsvn = input.pce_isvsvn.to_le_bytes().to_hex();
        let pce_id = input.pce_id.to_le_bytes().to_hex();
        let qe_id = match input.qe_id {
            Some(qe_id) => format!("&qeid={}", qe_id.to_hex()),
            None => String::new(),
        };
        let url = format!(
            "{}/sgx/certification/v{}/pckcert?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}{}",
            base_url, api_version, encrypted_ppid, cpusvn, pce_isvsvn, pce_id, qe_id
        );
        let headers = if let Some(api_key) = input.api_key {
            vec![(SUBSCRIPTION_KEY_HEADER.to_owned(), api_key.to_string())]
        } else {
            Vec::new()
        };
        Ok((url, headers))
    }

    fn validate_response(status_code: StatusCode) -> Result<(), Error> {
        match status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(
                status_code,
                "Cannot find the requested certificate",
            )),
            StatusCode::TooManyRequests => Err(Error::PCSError(status_code, "Too many requests")),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            _ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CERTIFICATE_ISSUER_CHAIN_HEADER)?;
        Ok(PckCert::new(response_body, ca_chain))
    }
}

#[derive(Hash)]
pub struct PckCrlIn {
    api_version: PcsVersion,
    ca: DcapArtifactIssuer,
}

impl WithApiVersion for PckCrlIn {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub struct PckCrlService;
impl ProvisioningServiceApi for PckCrlService {
    type Input<'a> = PckCrlIn;
    type Output = PckCrl<Unverified>;

    fn build_request(base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        let ca = match input.ca {
            DcapArtifactIssuer::PCKProcessorCA => "processor",
            DcapArtifactIssuer::PCKPlatformCA => "platform",
            DcapArtifactIssuer::SGXRootCA => {
                return Err(Error::PCSError(
                    StatusCode::BadRequest,
                    "Invalid ca parameter",
                ));
            }
        };
        let url = format!(
            "{}/sgx/certification/v{}/pckcrl?ca={}&encoding=pem",
            base_url, input.api_version as u8, ca,
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            __ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CRL_ISSUER_CHAIN_HEADER)?;
        let crl = PckCrl::new(response_body, ca_chain)?;
        Ok(crl)
    }
}

#[derive(Hash)]
pub struct QeIdIn {
    pub api_version: PcsVersion,
    pub tcb_evaluation_data_number: Option<u16>,
}

impl WithApiVersion for QeIdIn {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

struct QeIdService;
impl ProvisioningServiceApi for QeIdService {
    type Input<'a> = QeIdIn;
    type Output = QeIdentitySigned;

    fn build_request(base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let url = if let Some(tcb_evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/sgx/certification/v{}/qe/identity?tcbEvaluationDataNumber={}",
                base_url, api_version, tcb_evaluation_data_number
            )
        } else {
            format!(
                "{}/sgx/certification/v{}/qe/identity?update=early",
                base_url, api_version,
            )
        };
        Ok((url, Vec::new()))
    }

    fn validate_response(status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => {
                Err(Error::PCSError(status_code, "QE identity Cannot be found"))
            }
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            __ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, ENCLAVE_ID_ISSUER_CHAIN_HEADER)?;
        let id = QeIdentitySigned::parse(&response_body, ca_chain)?;
        Ok(id)
    }
}

#[derive(Hash)]
pub struct TcbInfoIn<'a> {
    pub(crate) api_version: PcsVersion,
    pub(crate) fmspc: &'a Fmspc,
    pub(crate) tcb_evaluation_data_number: Option<u16>,
}

impl WithApiVersion for TcbInfoIn<'_> {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

struct TcbInfoService<T> {
    _type: PhantomData<T>,
}
impl<T: PlatformTypeForTcbInfo + PlatformApiTag> ProvisioningServiceApi for TcbInfoService<T> {
    type Input<'a> = TcbInfoIn<'a>;
    type Output = TcbInfo<T>;

    fn build_request(base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let fmspc = input.fmspc.as_bytes().to_hex();
        let url = if let Some(evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/{}/certification/v{}/tcb?fmspc={}&tcbEvaluationDataNumber={}",
                base_url,
                T::tag(),
                api_version,
                fmspc,
                evaluation_data_number
            )
        } else {
            format!(
                "{}/{}/certification/v{}/tcb?fmspc={}&update=early",
                base_url,
                T::tag(),
                api_version,
                fmspc,
            )
        };
        Ok((url, Vec::new()))
    }

    fn validate_response(status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(status_code, "TCB info cannot be found")),
            StatusCode::Gone => Err(Error::PCSError(status_code, "TCB info no longer available")),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            __ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let key = match api_version {
            PcsVersion::V3 => TCB_INFO_ISSUER_CHAIN_HEADER_V3,
            PcsVersion::V4 => TCB_INFO_ISSUER_CHAIN_HEADER_V4,
        };
        let ca_chain = parse_issuer_header(&response_headers, key)?;
        let tcb_info = TcbInfo::parse(&response_body, ca_chain)?;
        Ok(tcb_info)
    }
}

#[derive(Hash)]
pub struct TcbEvaluationDataNumbersIn;

impl WithApiVersion for TcbEvaluationDataNumbersIn {
    fn api_version(&self) -> PcsVersion {
        PcsVersion::V4
    }
}

struct TcbEvaluationDataNumbersService<T: PlatformTypeForTcbInfo> {
    _type: PhantomData<T>
}
impl<T: PlatformTypeForTcbInfo + PlatformApiTag> ProvisioningServiceApi for TcbEvaluationDataNumbersService<T> {
    type Input<'a> = TcbEvaluationDataNumbersIn;
    type Output = RawTcbEvaluationDataNumbers<T>;

    fn build_request(base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        let url = format!(
            "{}/{}/certification/v{}/tcbevaluationdatanumbers",
            base_url,
            T::tag(),
            input.api_version() as u8,
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            __ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain =
            parse_issuer_header(&response_headers, TCB_EVALUATION_DATA_NUMBERS_ISSUER_CHAIN)?;
        RawTcbEvaluationDataNumbers::parse(&response_body, ca_chain).map_err(|e| e.into())
    }
}

pub struct ClientBuilder {
    retry_timeout: Option<Duration>,
    cache_capacity: usize,
    cache_shelf_time: Duration,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder {
            retry_timeout: None,
            cache_capacity: 10,
            cache_shelf_time: Duration::from_secs(60),
        }
    }
}

impl ClientBuilder {
    pub(crate) fn new() -> Self {
        ClientBuilder::default()
    }

    pub(crate) fn set_retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.retry_timeout = Some(retry_timeout);
        self
    }

    pub(crate) fn build<F: for<'a> Fetcher<'a>>(
        &self,
        base_url: &str,
        api_version: PcsVersion,
        fetcher: F,
    ) -> Client<F>
    {
        Client::new(
            base_url,
            api_version,
            fetcher,
            self.retry_timeout,
            self.cache_capacity,
            self.cache_shelf_time,
        )
    }
}

struct PcsService;
impl PcsService {

    fn call_service<'a, F: Fetcher<'a>, T: ProvisioningServiceApi>(
        fetcher: &'a F,
        base_url: &str,
        input: &T::Input<'_>,
    ) -> Result<T::Output, Error> {
        let (url, headers) = T::build_request(base_url, input)?;
        let req = fetcher.build_request(&url, headers)?;
        let api_version = input.api_version();

        let (status_code, resp) = fetcher.send(req)?;
        T::validate_response(status_code)?;
        let (response_body, response_headers) = fetcher.parse_response(resp)?;
        T::parse_response(
            response_body,
            response_headers,
            api_version,
        )
    }
}

struct CachedService<T: ProvisioningServiceApi> {
    service: BackoffService,
    cache: Mutex<LruCache<u64, (T::Output, SystemTime)>>,
    cache_shelf_time: Duration,
}

impl<T: ProvisioningServiceApi>
    CachedService<T>
{
    pub fn new(service: BackoffService, capacity: usize, cache_shelf_time: Duration) -> Self {
        Self {
            service,
            cache: Mutex::new(LruCache::new(capacity)),
            cache_shelf_time,
        }
    }
}

impl<T: ProvisioningServiceApi>
    CachedService<T>
{
    pub fn call_service<'a, F: Fetcher<'a>>(
        &self,
        fetcher: &'a F,
        base_url: &str,
        input: &T::Input<'_>,
    ) -> Result<T::Output, Error> {
        let key = {
            let mut hasher = DefaultHasher::new();
            input.hash(&mut hasher);
            hasher.finish()
        };

        let mut cache = self.cache.lock().unwrap();
        if let Some((value, time)) = cache.get_mut(&key) {
            if self.cache_shelf_time < time.elapsed().unwrap_or(Duration::MAX) {
                cache.remove(&key);
            } else {
                return Ok(value.to_owned());
            }
        }
        let value = self.service.call_service::<F, T>(fetcher, base_url, input)?;
        cache.insert(key, (value.clone(), SystemTime::now()));
        Ok(value)
    }
}

struct BackoffService {
    retry_timeout: Option<Duration>,
}

impl BackoffService {
    pub fn new(retry_timeout: Option<Duration>) -> Self {
        Self {
            retry_timeout,
        }
    }
}

impl BackoffService {
    const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(2);
    const RETRY_INTERVAL_MULTIPLIER: f64 = 2.0;

    pub fn call_service<'a, F: Fetcher<'a>, T: ProvisioningServiceApi>(
        &self,
        fetcher: &'a F,
        base_url: &str,
        input: &T::Input<'_>,
    ) -> Result<T::Output, Error> {
        if let Some(retry_timeout) = self.retry_timeout {
            let op = || match PcsService::call_service::<F, T>(fetcher, base_url, input) {
                Ok(output) => Ok(output),
                Err(err) => match err {
                    Error::PCSError(status_code, msg) => {
                        if status_code.clone() as u16 >= 500 {
                            Err(backoff::Error::transient(Error::PCSError(status_code, msg)))
                        } else {
                            Err(backoff::Error::permanent(Error::PCSError(status_code, msg)))
                        }
                    }
                    err @ _ => Err(backoff::Error::Permanent(err)),
                },
            };

            let backoff = backoff::ExponentialBackoffBuilder::default()
                .with_initial_interval(Self::RETRY_INITIAL_INTERVAL)
                .with_multiplier(Self::RETRY_INTERVAL_MULTIPLIER)
                .with_max_elapsed_time(Some(retry_timeout))
                .build();
            backoff::retry(backoff, op).map_err(|backoff_err| match backoff_err {
                backoff::Error::Permanent(err) => err,
                backoff::Error::Transient { err, .. } => err,
            })
        } else {
            PcsService::call_service::<F, T>(fetcher, base_url, input)
        }
    }
}

pub struct Client<F: for<'a> Fetcher<'a>>
{
    base_url: String,
    api_version: PcsVersion,
    qeid_service: CachedService<QeIdService>,
    sgx_tcbinfo_service: CachedService<TcbInfoService<platform::SGX>>,
    tdx_tcbinfo_service: CachedService<TcbInfoService<platform::TDX>>,
    sgx_tcb_evaluation_data_numbers_service: CachedService<TcbEvaluationDataNumbersService<platform::SGX>>,
    tdx_tcb_evaluation_data_numbers_service: CachedService<TcbEvaluationDataNumbersService<platform::TDX>>,
    fetcher: F,
}

impl<F: for<'a> Fetcher<'a>> Client<F>
{
    fn new(
        base_url: &str,
        api_version: PcsVersion,
        fetcher: F,
        retry_timeout: Option<Duration>,
        cache_capacity: usize,
        cache_shelf_time: Duration,
    ) -> Self
    {
        Client {
            base_url: base_url.to_owned(),
            api_version,
            qeid_service: CachedService::new(
                BackoffService::new(
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            sgx_tcbinfo_service: CachedService::new(
                BackoffService::new(
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            tdx_tcbinfo_service: CachedService::new(
                BackoffService::new(
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            sgx_tcb_evaluation_data_numbers_service: CachedService::new(
                BackoffService::new(
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            tdx_tcb_evaluation_data_numbers_service: CachedService::new(
                BackoffService::new(
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            fetcher,
        }
    }
}

pub trait ProvisioningClient {
    fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error>;

    fn pckcert(
        &self,
        api_key: &Option<String>,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&QeId>,
    ) -> Result<PckCert<Unverified>, Error>;

    fn sgx_tcbinfo(&self, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::SGX>, Error>;

    fn tdx_tcbinfo(&self, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::TDX>, Error>;

    fn pckcrl(&self, ca: DcapArtifactIssuer) -> Result<PckCrl<Unverified>, Error>;

    fn qe_identity(&self, evaluation_data_number: Option<u16>) -> Result<QeIdentitySigned, Error>;

    fn sgx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::SGX>, Error>;

    fn tdx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::TDX>, Error>;
}


pub trait ProvisioningClientFuncSelector: PlatformTypeForTcbInfo {
    fn get_tcb_evaluation_data_numbers(pc: &dyn ProvisioningClient) -> Result<RawTcbEvaluationDataNumbers<Self>, Error>;
    fn get_tcbinfo(pc: &dyn ProvisioningClient, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<Self>, Error>;
}

impl ProvisioningClientFuncSelector for platform::SGX {
    fn get_tcb_evaluation_data_numbers(pc: &dyn ProvisioningClient) -> Result<RawTcbEvaluationDataNumbers<platform::SGX>, Error> {
        pc.sgx_tcb_evaluation_data_numbers()
    }

    fn get_tcbinfo(pc: &dyn ProvisioningClient, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::SGX>, Error> {
        pc.sgx_tcbinfo(fmspc, evaluation_data_number)
    }
}

impl ProvisioningClientFuncSelector for platform::TDX {
    fn get_tcb_evaluation_data_numbers(pc: &dyn ProvisioningClient) -> Result<RawTcbEvaluationDataNumbers<platform::TDX>, Error> {
        pc.tdx_tcb_evaluation_data_numbers()
    }

    fn get_tcbinfo(pc: &dyn ProvisioningClient, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::TDX>, Error> {
        pc.tdx_tcbinfo(fmspc, evaluation_data_number)
    }
}


impl<F: for<'a> Fetcher<'a>> ProvisioningClient for Client<F>
{
    fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
        todo!()
    }

    // fn pckcerts(&self, api_key: &Option<String>, encrypted_ppid: &EncPpid, pce_id: PceId) -> Result<PckCerts, Error> {
    //     let input = PckCertsIn { enc_ppid: encrypted_ppid, pce_id, api_key, api_version: self.api_version };
    //     self.pckcerts_service.call_service(&self.fetcher, &self.base_url, &input)
    // }

    // fn pckcert(
    //     &self,
    //     api_key: &Option<String>,
    //     encrypted_ppid: Option<&EncPpid>,
    //     pce_id: &PceId,
    //     cpu_svn: &CpuSvn,
    //     pce_isvsvn: PceIsvsvn,
    //     qe_id: Option<&QeId>,
    // ) -> Result<PckCert<Unverified>, Error> {
    //     let input = self.pckcert_service.pcs_service().build_input(self.api_version, encrypted_ppid, pce_id, cpu_svn, pce_isvsvn, qe_id, api_key, None, None);
    //     self.pckcert_service.call_service(&self.fetcher, &self.base_url, &input)
    // }

    /// Retrieve PCK certificates when `pckcerts` Rest API is not supported
    /// using the following method:
    /// 1. Call `pckcert()` with PCK ID to get best available PCK cert.
    /// 2. Try to call `pckcert()` with PCK ID but with CPUSVN all 1's.
    /// 3. Using the FMSPC value from PCK cert in step 1, call `tcbinfo()` to
    ///    get TCB info.
    /// 4. For each TCB level in the result of previous call:
    ///     - Call `pckcert()` to get the best available PCK cert for that TCB
    ///       level.
    ///     - When late microcode value is higher than the early microcode
    ///       value, also try to get PCK cert with TCB level where the early
    ///       microcode value is set to the late microcode value.
    ///
    /// Note that PCK certs for some TCB levels may be missing.
    // fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
    //     let get_and_collect = |collection: &mut BTreeMap<([u8; 16], u16), PckCert<Unverified>>, cpu_svn: &[u8; 16], pce_svn: u16| -> Result<PckCert<Unverified>, Error> {
    //         let pck_cert = self.pckcert(
    //             api_key,
    //             Some(&pck_id.enc_ppid),
    //             &pck_id.pce_id,
    //             cpu_svn,
    //             pce_svn,
    //             Some(&pck_id.qe_id),
    //         )?;

    //         // Getting PCK cert using CPUSVN from PCKID
    //         let ptcb = pck_cert.platform_tcb()?;
    //         collection.insert((ptcb.cpusvn, ptcb.tcb_components.pce_svn()), pck_cert.clone());
    //         Ok(pck_cert)
    //     };

    //     // Use BTreeMap to have an ordered PckCerts at the end
    //     let mut pckcerts_map = BTreeMap::new();

    //     // 1. Use PCK ID to get best available PCK Cert
    //     let pck_cert = get_and_collect(&mut pckcerts_map, &pck_id.cpu_svn, pck_id.pce_isvsvn)?;

    //     // 2. Getting PCK cert using CPUSVN all 1's
    //     let _ign_err = get_and_collect(&mut pckcerts_map, &[u8::MAX; 16], pck_id.pce_isvsvn);

    //     let fmspc = pck_cert.sgx_extension()?.fmspc;
    //     let tcb_info = self.sgx_tcbinfo(&fmspc, None)?;
    //     let tcb_data = tcb_info.data()?;
    //     for (cpu_svn, pce_isvsvn) in tcb_data.iter_tcb_components() {
    //         // 3. Get PCK based on TCB levels
    //         let _ = get_and_collect(&mut pckcerts_map, &cpu_svn, pce_isvsvn)?;

    //         // 4. If late loaded microcode version is higher than early loaded microcode,
    //         //    also try with highest microcode version of both components. We found cases where
    //         //    fetching the PCK Cert that exactly matched the TCB level, did not result in a PCK
    //         //    Cert for that level
    //         let early_ucode_idx = tcb_data.tcb_component_index(TcbComponentType::EarlyMicrocodeUpdate);
    //         let late_ucode_idx = tcb_data.tcb_component_index(TcbComponentType::LateMicrocodeUpdate);
    //         if let (Some(early_ucode_idx), Some(late_ucode_idx)) = (early_ucode_idx, late_ucode_idx) {
    //             let early_ucode = cpu_svn[early_ucode_idx];
    //             let late_ucode = cpu_svn[late_ucode_idx];
    //             if early_ucode < late_ucode {
    //                 let mut cpu_svn = cpu_svn.clone();
    //                 cpu_svn[early_ucode_idx] = late_ucode;
    //                 let _ign_err = get_and_collect(&mut pckcerts_map, &cpu_svn, pce_isvsvn);
    //             }
    //         }
    //     }

    //     // BTreeMap by default is Ascending
    //     let pck_certs: Vec<_> = pckcerts_map.into_iter().rev().map(|(_, v)| v).collect();
    //     pck_certs
    //         .try_into()
    //         .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))
    // }
    
    fn pckcrl(&self, ca: DcapArtifactIssuer) -> Result<PckCrl<Unverified>, Error> {
        todo!()
    }

    fn sgx_tcbinfo(&self, fmspc: &Fmspc, tcb_evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::SGX>, Error> {
        let input = TcbInfoIn { api_version: self.api_version, fmspc, tcb_evaluation_data_number };
        self.sgx_tcbinfo_service.call_service(&self.fetcher, &self.base_url, &input)
    }

    fn tdx_tcbinfo(&self, fmspc: &Fmspc, tcb_evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::TDX>, Error> {
        let input = TcbInfoIn { api_version: self.api_version, fmspc, tcb_evaluation_data_number };
        self.tdx_tcbinfo_service.call_service(&self.fetcher, &self.base_url, &input)
    }

    fn qe_identity(&self, tcb_evaluation_data_number: Option<u16>) -> Result<QeIdentitySigned, Error> {
        let input = QeIdIn { api_version: self.api_version, tcb_evaluation_data_number };
        self.qeid_service.call_service(&self.fetcher, &self.base_url, &input)
    }

    fn sgx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::SGX>, Error> {
        let input = TcbEvaluationDataNumbersIn;
        self.sgx_tcb_evaluation_data_numbers_service.call_service(&self.fetcher, &self.base_url, &input)
    }

    fn tdx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::TDX>, Error> {
        let input = TcbEvaluationDataNumbersIn;
        self.tdx_tcb_evaluation_data_numbers_service.call_service(&self.fetcher, &self.base_url, &input)
    }
    
    fn pckcert(
        &self,
        api_key: &Option<String>,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&QeId>,
    ) -> Result<PckCert<Unverified>, Error> {
        todo!()
    }
}

pub trait Fetcher<'req> {
    type Request;
    type Response;

    fn build_request(
        &'req self,
        url: &String,
        headers: Vec<(String, String)>,
    ) -> Result<Self::Request, Error>;

    fn send(&'req self, request: Self::Request) -> Result<(StatusCode, Self::Response), Error>;

    fn parse_response(
        &'req self,
        response: Self::Response,
    ) -> Result<(String, Vec<(String, String)>), Error>;
}

#[cfg(feature = "reqwest")]
impl<'req> Fetcher<'req> for ReqwestClient {
    type Request = reqwest::blocking::RequestBuilder;
    type Response = ReqwestResponse;

    fn build_request(
        &'req self,
        url: &String,
        headers: Vec<(String, String)>,
    ) -> Result<Self::Request, Error> {
        let url = reqwest::Url::parse(url).map_err(|e| e.to_string())?;

        let mut result = self.get(url);

        for (name, value) in headers {
            result = result.header(name, value);
        }

        Ok(result)
    }

    fn send(&'req self, request: Self::Request) -> Result<(StatusCode, Self::Response), Error> {
        use std::fmt::Write;
        // Reqwest does not provide enough info about error
        fn report(mut err: &(dyn std::error::Error + 'static)) -> String {
            let mut s = format!("{}", err);
            while let Some(src) = err.source() {
                let _ = write!(s, "\n  Caused by: {}", src);
                err = src;
            }
            s
        }
        let response = request.send().map_err(|e| report(&e))?;
        let status_code =
            StatusCode::try_from(response.status().as_u16()).map_err(|e| e.to_string())?;

        Ok((status_code, response))
    }

    fn parse_response(
        &'req self,
        mut response: Self::Response,
    ) -> Result<(String, Vec<(String, String)>), Error> {
        let mut body = Vec::new();
        response.read_to_end(&mut body).map_err(|e| {
            Error::ReadResponseError(
                format!("Error while trying to read response body. Error: {}", e).into(),
            )
        })?;

        let body = String::from_utf8(body)
            .map_err(|e| Error::ReadResponseError(format!("{}", e).into()))?;

        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(header, value)| (header.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();
        Ok((body, headers))
    }
}

pub trait ProvisioningServiceApi {
    type Input<'a>: WithApiVersion + Hash;
    type Output: Clone;

    fn build_request(
        base_url: &str,
        input: &Self::Input<'_>,
    ) -> Result<(String, Vec<(String, String)>), Error>;

    fn validate_response(code: StatusCode) -> Result<(), Error>;

    fn parse_response(
        response_body: String,
        response_headers: Vec<(String, String)>,
        api_version: PcsVersion,
    ) -> Result<Self::Output, Error>;
}

#[cfg(test)]
mod test_helpers {
    use pkix::FromBer;

    pub fn get_cert_subject(cert: &str) -> String {
        let cert = &pkix::pem::pem_to_der(cert.trim(), Some(pkix::pem::PEM_CERTIFICATE))
            .ok_or(yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
            .unwrap();
        let cert = pkix::x509::GenericCertificate::from_ber(&cert).unwrap();
        let name = cert.tbscert.subject.get(&*pkix::oid::commonName).unwrap();
        String::from_utf8_lossy(&name.value()).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::String;

    struct MockService;

    #[derive(Hash, Clone, PartialEq, Eq, Debug)]
    struct MockInput(u64);

    impl WithApiVersion for MockInput {
        fn api_version(&self) -> PcsVersion {
            PcsVersion::V3
        }
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct MockOutput(String);

    impl ProvisioningServiceApi for MockService {
        type Input<'a> = MockInput;
        type Output = MockOutput;

        fn build_request(
            _base_url: &str,
            _input: &Self::Input<'_>,
        ) -> Result<(String, Vec<(String, String)>), Error> {
            Ok((_input.0.to_string(), vec![]))
        }

        fn validate_response(_code: StatusCode) -> Result<(), Error> {
            Ok(())
        }

        fn parse_response(
            response_body: String,
            _response_headers: Vec<(std::string::String, std::string::String)>,
            _api_version: PcsVersion,
        ) -> Result<Self::Output, Error> {
            Ok(MockOutput(format!("response to: {}", response_body)))
        }
    }

    struct MockFetcher;

    impl<'req> Fetcher<'req> for MockFetcher {
        type Request = String;
        type Response = String;

        fn build_request(
            &'req self,
            url: &String,
            _headers: Vec<(String, String)>,
        ) -> Result<Self::Request, Error> {
            Ok(url.clone())
        }

        fn send(&'req self, request: Self::Request) -> Result<(StatusCode, Self::Response), Error> {
            Ok((StatusCode::Ok, request))
        }

        fn parse_response(
            &'req self,
            response: Self::Response,
        ) -> Result<(String, Vec<(String, String)>), Error> {
            Ok((response, vec![]))
        }
    }

    #[test]
    fn test_call_service_cache_miss() {
        let service = BackoffService::new(None);
        let cached_service: CachedService<MockService> = CachedService::new(service, 5, Duration::from_secs(120));
        let fetcher = MockFetcher;
        let input_a = MockInput(42);
        let input_b = MockInput(420);

        // Initial call to populate the cache for `input_a`
        cached_service.call_service(&fetcher, "", &input_a).unwrap();

        // input_b should provoke cache miss and add new key to the cache
        let result = cached_service.call_service(&fetcher, "", &input_b).unwrap();

        let (cached_value, _) = {
            let mut cache = cached_service.cache.lock().unwrap();
            cache.get_mut(&calculate_key(&input_b)).unwrap().to_owned()
        };

        assert_eq!(result, cached_value);
    }

    #[test]
    fn test_call_service_cache_hit() {
        let service = BackoffService::new(None);
        let cached_service: CachedService<MockService> = CachedService::new(service, 5, Duration::from_secs(120));
        let fetcher = MockFetcher;
        let input = MockInput(42);

        // Initial call to populate the cache
        let _ = cached_service.call_service(&fetcher, "", &input).unwrap();

        // Now the service should not be called, and the cached result should be returned
        let (cached_value, _) = {
            let mut cache = cached_service.cache.lock().unwrap();
            cache.get_mut(&calculate_key(&input)).unwrap().to_owned()
        };

        let result = cached_service.call_service(&fetcher, "", &input).unwrap();
        assert_eq!(result, cached_value);
    }

    #[test]
    fn test_cache_capacity_eviction() {
        let service = BackoffService::new(None);
        let cached_service = CachedService::<MockService>::new(service, 2, Duration::from_secs(120));
        let fetcher = MockFetcher;

        // Insert entries into the cache, exceeding its capacity
        for i in 0..3 {
            let input = MockInput(i);
            let _ = cached_service.call_service(&fetcher, "", &input).unwrap();
        }

        // At this point, the cache should have evicted the first inserted entry (MockInput(0))
        let mut cache = cached_service.cache.lock().unwrap();

        // The cache should only have 2 items (capacity is 2)
        assert_eq!(cache.len(), 2);

        // The first inserted key (MockInput(0)) should be evicted
        let key_first = calculate_key(&MockInput(0));
        assert!(!cache.contains_key(&key_first));

        // The last inserted key (MockInput(2)) should be present
        let key_last = calculate_key(&MockInput(2));
        assert!(cache.contains_key(&key_last));
    }

    // Helper function to calculate the cache key based on the input
    fn calculate_key(input: &MockInput) -> u64 {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    }
}
