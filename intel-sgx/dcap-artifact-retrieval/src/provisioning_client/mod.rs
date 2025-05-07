/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use lru_cache::LruCache;
use num_enum::TryFromPrimitive;
use pcs::{
    CpuSvn, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl, PckID, QeId,
    QeIdentitySigned, TcbInfo, RawTcbEvaluationDataNumbers, Unverified,
};
#[cfg(feature = "reqwest")]
use reqwest::blocking::{Client as ReqwestClient, Response as ReqwestResponse};

use crate::Error;

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

pub trait PckCertsService<'inp>:
    ProvisioningServiceApi<'inp, Input = PckCertsIn<'inp>, Output = PckCerts>
{
    fn build_input(
        &'inp self,
        enc_ppid: &'inp EncPpid,
        pce_id: PceId,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input;
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

pub trait PckCertService<'inp>:
    ProvisioningServiceApi<'inp, Input = PckCertIn<'inp>, Output = PckCert<Unverified>>
{
    fn build_input(
        &'inp self,
        encrypted_ppid: Option<&'inp EncPpid>,
        pce_id: &'inp PceId,
        cpu_svn: &'inp CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&'inp QeId>,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

#[derive(Copy, Clone, Debug, Hash)]
pub enum PckCA {
    Platform,
    Processor,
}

#[derive(Hash)]
pub struct PckCrlIn {
    api_version: PcsVersion,
    ca: PckCA,
}

impl WithApiVersion for PckCrlIn {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub trait PckCrlService<'inp>:
    ProvisioningServiceApi<'inp, Input = PckCrlIn, Output = PckCrl<Unverified>>
{
    fn build_input(&'inp self, ca: PckCA) -> <Self as ProvisioningServiceApi<'inp>>::Input;
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

pub trait QeIdService<'inp>:
    ProvisioningServiceApi<'inp, Input = QeIdIn, Output = QeIdentitySigned>
{
    fn build_input(&'inp self, tcb_evaluation_data_number: Option<u16>) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

#[derive(Hash)]
pub struct TcbInfoIn<'i> {
    pub(crate) api_version: PcsVersion,
    pub(crate) fmspc: &'i Fmspc,
    pub(crate) tcb_evaluation_data_number: Option<u16>,
}

impl WithApiVersion for TcbInfoIn<'_> {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub trait TcbInfoService<'inp>:
    ProvisioningServiceApi<'inp, Input = TcbInfoIn<'inp>, Output = TcbInfo>
{
    fn build_input(&'inp self, fmspc: &'inp Fmspc, tcb_evaluation_data_number: Option<u16>)
        -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

#[derive(Hash)]
pub struct TcbEvaluationDataNumbersIn;

impl WithApiVersion for TcbEvaluationDataNumbersIn {
    fn api_version(&self) -> PcsVersion {
        PcsVersion::V4
    }
}

pub trait TcbEvaluationDataNumbersService<'inp>:
    ProvisioningServiceApi<'inp, Input = TcbEvaluationDataNumbersIn, Output = RawTcbEvaluationDataNumbers>
{
    fn build_input(&self)
        -> <Self as ProvisioningServiceApi<'inp>>::Input;
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

    pub(crate) fn build<PSS, PS, PC, QS, TS, ES, F>(
        self,
        pckcerts_service: PSS,
        pckcert_service: PS,
        pckcrl_service: PC,
        qeid_service: QS,
        tcbinfo_service: TS,
        tcb_evaluation_data_numbers_service: ES,
        fetcher: F,
    ) -> Client<F>
    where
        PSS: for<'a> PckCertsService<'a> + Sync + Send + 'static,
        PS: for<'a> PckCertService<'a> + Sync + Send + 'static,
        PC: for<'a> PckCrlService<'a> + Sync + Send + 'static,
        QS: for<'a> QeIdService<'a> + Sync + Send + 'static,
        TS: for<'a> TcbInfoService<'a> + Sync + Send + 'static,
        ES: for<'a> TcbEvaluationDataNumbersService<'a> + Sync + Send + 'static,
        F: for<'a> Fetcher<'a>,
    {
        Client::new(
            pckcerts_service,
            pckcert_service,
            pckcrl_service,
            qeid_service,
            tcbinfo_service,
            tcb_evaluation_data_numbers_service,
            fetcher,
            self.retry_timeout,
            self.cache_capacity,
            self.cache_shelf_time,
        )
    }
}

struct PcsService<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> {
    service: Box<T>,
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> PcsService<T> {
    pub fn new(service: Box<T>) -> Self {
        Self { service }
    }
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> PcsService<T> {
    pub(crate) fn pcs_service(&self) -> &T {
        &self.service
    }

    fn call_service<'a, F: Fetcher<'a>>(
        &'a self,
        fetcher: &'a F,
        input: &<T as ProvisioningServiceApi<'a>>::Input,
    ) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
        let (url, headers) =
            <T as ProvisioningServiceApi<'a>>::build_request(&self.pcs_service(), input)?;
        let req = fetcher.build_request(&url, headers)?;
        let api_version = input.api_version();

        let (status_code, resp) = fetcher.send(req)?;
        <T as ProvisioningServiceApi<'a>>::validate_response(self.pcs_service(), status_code)?;
        let (response_body, response_headers) = fetcher.parse_response(resp)?;
        <T as ProvisioningServiceApi<'a>>::parse_response(
            self.pcs_service(),
            response_body,
            response_headers,
            api_version,
        )
    }
}

struct CachedService<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized> {
    service: BackoffService<T>,
    cache: Mutex<LruCache<u64, (O, SystemTime)>>,
    cache_shelf_time: Duration,
}

impl<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized>
    CachedService<O, T>
{
    pub fn new(service: BackoffService<T>, capacity: usize, cache_shelf_time: Duration) -> Self {
        Self {
            service,
            cache: Mutex::new(LruCache::new(capacity)),
            cache_shelf_time,
        }
    }
}

impl<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized>
    CachedService<O, T>
{
    pub(crate) fn pcs_service(&self) -> &T {
        &self.service.pcs_service()
    }

    pub fn call_service<'a, F: Fetcher<'a>>(
        &'a self,
        fetcher: &'a F,
        input: &<T as ProvisioningServiceApi<'a>>::Input,
    ) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
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
        let value = self.service.call_service::<F>(fetcher, input)?;
        cache.insert(key, (value.clone(), SystemTime::now()));
        Ok(value)
    }
}

struct BackoffService<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> {
    service: PcsService<T>,
    retry_timeout: Option<Duration>,
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> BackoffService<T> {
    pub fn new(service: PcsService<T>, retry_timeout: Option<Duration>) -> Self {
        Self {
            service,
            retry_timeout,
        }
    }
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> BackoffService<T> {
    const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(2);
    const RETRY_INTERVAL_MULTIPLIER: f64 = 2.0;

    pub(crate) fn pcs_service(&self) -> &T {
        &self.service.pcs_service()
    }

    pub fn call_service<'a, F: Fetcher<'a>>(
        &'a self,
        fetcher: &'a F,
        input: &<T as ProvisioningServiceApi<'a>>::Input,
    ) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
        if let Some(retry_timeout) = self.retry_timeout {
            let op = || match self.service.call_service::<F>(fetcher, input) {
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
            self.service.call_service::<F>(fetcher, input)
        }
    }
}

pub struct Client<F: for<'a> Fetcher<'a>> {
    pckcerts_service: CachedService<PckCerts, dyn for<'a> PckCertsService<'a> + Sync + Send>,
    pckcert_service:
        CachedService<PckCert<Unverified>, dyn for<'a> PckCertService<'a> + Sync + Send>,
    pckcrl_service: CachedService<PckCrl<Unverified>, dyn for<'a> PckCrlService<'a> + Sync + Send>,
    qeid_service: CachedService<QeIdentitySigned, dyn for<'a> QeIdService<'a> + Sync + Send>,
    tcbinfo_service: CachedService<TcbInfo, dyn for<'a> TcbInfoService<'a> + Sync + Send>,
    tcb_evaluation_data_numbers_service: CachedService<RawTcbEvaluationDataNumbers, dyn for<'a> TcbEvaluationDataNumbersService<'a> + Sync + Send>,
    fetcher: F,
}

impl<F: for<'a> Fetcher<'a>> Client<F> {
    fn new<PSS, PS, PC, QS, TS, ES>(
        pckcerts_service: PSS,
        pckcert_service: PS,
        pckcrl_service: PC,
        qeid_service: QS,
        tcbinfo_service: TS,
        tcb_evaluation_data_numbers_service: ES,
        fetcher: F,
        retry_timeout: Option<Duration>,
        cache_capacity: usize,
        cache_shelf_time: Duration,
    ) -> Client<F>
    where
        PSS: for<'a> PckCertsService<'a> + Sync + Send + 'static,
        PS: for<'a> PckCertService<'a> + Sync + Send + 'static,
        PC: for<'a> PckCrlService<'a> + Sync + Send + 'static,
        QS: for<'a> QeIdService<'a> + Sync + Send + 'static,
        TS: for<'a> TcbInfoService<'a> + Sync + Send + 'static,
        ES: for<'a> TcbEvaluationDataNumbersService<'a> + Sync + Send + 'static,
    {
        Client {
            pckcerts_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(pckcerts_service)),
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            pckcert_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(pckcert_service)),
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            pckcrl_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(pckcrl_service)),
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            qeid_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(qeid_service)),
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            tcbinfo_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(tcbinfo_service)),
                    retry_timeout.clone(),
                ),
                cache_capacity,
                cache_shelf_time,
            ),
            tcb_evaluation_data_numbers_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(Box::new(tcb_evaluation_data_numbers_service)),
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
    fn pckcerts(&self, enc_ppid: &EncPpid, pce_id: PceId) -> Result<PckCerts, Error>;

    fn pckcert(
        &self,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&QeId>,
    ) -> Result<PckCert<Unverified>, Error>;

    fn tcbinfo(&self, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo, Error>;

    fn pckcrl(&self, ca: PckCA) -> Result<PckCrl<Unverified>, Error>;

    fn qe_identity(&self, evaluation_data_number: Option<u16>) -> Result<QeIdentitySigned, Error>;

    /// Retrieve PCK certificates using `pckcerts()` and fallback to the
    /// following method if that's not supported:
    /// - Call `pckcert()` to find the FMSPC.
    /// - Using the FMSPC value, call `tcbinfo()` to get TCB info.
    /// - For each TCB level in the result of previous call:
    ///   - Call `pckcert()` to get the best available PCK cert for that TCB level.
    /// Note that PCK certs for some TCB levels may be missing.
    fn pckcerts_with_fallback(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
        match self.pckcerts(&pck_id.enc_ppid, pck_id.pce_id) {
            Ok(pck_certs) => return Ok(pck_certs),
            Err(Error::RequestNotSupported) => {} // fallback below
            Err(e) => return Err(e),
        }
        // fallback:

        // NOTE: at least with PCCS, any call to `pckcert()` will return the
        // "best available" PCK cert for the specified TCB level.
        let pck_cert = self.pckcert(
            Some(&pck_id.enc_ppid),
            &pck_id.pce_id,
            &pck_id.cpu_svn,
            pck_id.pce_isvsvn,
            Some(&pck_id.qe_id),
        )?;
        let fmspc = pck_cert.sgx_extension()?.fmspc;
        let tcb_info = self.tcbinfo(&fmspc, None)?;
        let tcb_data = tcb_info.data()?;
        let mut pcks = HashMap::new();
        for (cpu_svn, pce_isvsvn) in tcb_data.iter_tcb_components() {
            let p = match self.pckcert(
                Some(&pck_id.enc_ppid),
                &pck_id.pce_id,
                &cpu_svn,
                pce_isvsvn,
                Some(&pck_id.qe_id),
            ) {
                Ok(cert) => cert,
                Err(Error::PCSError(StatusCode::NotFound, _)) |
                Err(Error::PCSError(StatusCode::NonStandard462, _)) => continue,
                Err(other) => return Err(other)
            };
            let ptcb = p.platform_tcb()?;
            pcks.insert((ptcb.cpusvn, ptcb.tcb_components.pce_svn()), p);
        }
        let pcks: Vec<_> = pcks.into_iter().map(|(_, v)| v).collect();
        pcks
            .try_into()
            .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))
    }

    fn tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers, Error>;
}

impl<F: for<'a> Fetcher<'a>> ProvisioningClient for Client<F> {
    fn pckcerts(&self, encrypted_ppid: &EncPpid, pce_id: PceId) -> Result<PckCerts, Error> {
        let input = self
            .pckcerts_service
            .pcs_service()
            .build_input(encrypted_ppid, pce_id);
        self.pckcerts_service.call_service(&self.fetcher, &input)
    }

    fn pckcert(
        &self,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&QeId>,
    ) -> Result<PckCert<Unverified>, Error> {
        let input = self.pckcert_service.pcs_service().build_input(
            encrypted_ppid,
            pce_id,
            cpu_svn,
            pce_isvsvn,
            qe_id,
        );
        self.pckcert_service.call_service(&self.fetcher, &input)
    }

    fn tcbinfo(&self, fmspc: &Fmspc, tcb_evaluation_data_number: Option<u16>) -> Result<TcbInfo, Error> {
        let input = self.tcbinfo_service.pcs_service().build_input(fmspc, tcb_evaluation_data_number);
        self.tcbinfo_service.call_service(&self.fetcher, &input)
    }

    fn pckcrl(&self, ca: PckCA) -> Result<PckCrl<Unverified>, Error> {
        let input = self.pckcrl_service.pcs_service().build_input(ca);
        self.pckcrl_service.call_service(&self.fetcher, &input)
    }

    fn qe_identity(&self, tcb_evaluation_data_number: Option<u16>) -> Result<QeIdentitySigned, Error> {
        let input = self.qeid_service.pcs_service().build_input(tcb_evaluation_data_number);
        self.qeid_service.call_service(&self.fetcher, &input)
    }

    fn tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers, Error> {
        let input = self.tcb_evaluation_data_numbers_service.pcs_service().build_input();
        self.tcb_evaluation_data_numbers_service.call_service(&self.fetcher, &input)
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

pub trait ProvisioningServiceApi<'inp> {
    type Input: 'inp + WithApiVersion + Hash;
    type Output: Clone;

    fn build_request(
        &'inp self,
        input: &Self::Input,
    ) -> Result<(String, Vec<(String, String)>), Error>;

    fn validate_response(&'inp self, code: StatusCode) -> Result<(), Error>;

    fn parse_response(
        &'inp self,
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

    impl<'a> ProvisioningServiceApi<'a> for MockService {
        type Input = MockInput;
        type Output = MockOutput;

        fn build_request(
            &'a self,
            _input: &Self::Input,
        ) -> Result<(String, Vec<(String, String)>), Error> {
            Ok((_input.0.to_string(), vec![]))
        }

        fn validate_response(&'a self, _code: StatusCode) -> Result<(), Error> {
            Ok(())
        }

        fn parse_response(
            &'a self,
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
        let service = PcsService {
            service: Box::new(MockService),
        };
        let service = BackoffService::new(service, None);
        let cached_service = CachedService::new(service, 5, Duration::from_secs(120));
        let fetcher = MockFetcher;
        let input_a = MockInput(42);
        let input_b = MockInput(420);

        // Initial call to populate the cache for `input_a`
        cached_service.call_service(&fetcher, &input_a).unwrap();

        // input_b should provoke cache miss and add new key to the cache
        let result = cached_service.call_service(&fetcher, &input_b).unwrap();

        let (cached_value, _) = {
            let mut cache = cached_service.cache.lock().unwrap();
            cache.get_mut(&calculate_key(&input_b)).unwrap().to_owned()
        };

        assert_eq!(result, cached_value);
    }

    #[test]
    fn test_call_service_cache_hit() {
        let service = PcsService {
            service: Box::new(MockService),
        };
        let service = BackoffService::new(service, None);
        let cached_service = CachedService::new(service, 5, Duration::from_secs(120));
        let fetcher = MockFetcher;
        let input = MockInput(42);

        // Initial call to populate the cache
        let _ = cached_service.call_service(&fetcher, &input).unwrap();

        // Now the service should not be called, and the cached result should be returned
        let (cached_value, _) = {
            let mut cache = cached_service.cache.lock().unwrap();
            cache.get_mut(&calculate_key(&input)).unwrap().to_owned()
        };

        let result = cached_service.call_service(&fetcher, &input).unwrap();
        assert_eq!(result, cached_value);
    }

    #[test]
    fn test_cache_capacity_eviction() {
        let service = PcsService {
            service: Box::new(MockService),
        };
        let service = BackoffService::new(service, None);
        let cached_service = CachedService::new(service, 2, Duration::from_secs(120));
        let fetcher = MockFetcher;

        // Insert entries into the cache, exceeding its capacity
        for i in 0..3 {
            let input = MockInput(i);
            let _ = cached_service.call_service(&fetcher, &input).unwrap();
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
