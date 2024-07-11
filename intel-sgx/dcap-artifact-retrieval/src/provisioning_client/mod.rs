use std::convert::TryFrom;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use lru_cache::LruCache;
use num_enum::TryFromPrimitive;
use pcs::{CpuSvn, EncPpid, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl, QeId, QeIdentitySigned, TcbInfo, Unverified};
#[cfg(feature = "reqwest")]
use reqwest::blocking::{Client as ReqwestClient, Response as ReqwestResponse};

use crate::Error;

mod azure;
mod intel;

pub use azure::AzureProvisioningClientBuilder;
pub use intel::IntelProvisioningClientBuilder;

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
    //452-499	Unassigned,
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
    #[num_enum(alternatives = [104..=199, 209..=225, 227..=299, 309..=399, 419, 420, 427, 430, 432..=450, 452..=499, 509, 512..=598])]
    Unassigned = 599,
}

#[derive(Copy, Clone, PartialEq, Eq)]
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

pub trait PckCertsService<'inp> : ProvisioningServiceApi<'inp, Input = PckCertsIn<'inp>, Output = PckCerts> {
    fn build_input(&'inp self, enc_ppid: &'inp EncPpid, pce_id: PceId) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

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

pub trait PckCertService<'inp> : ProvisioningServiceApi<'inp, Input = PckCertIn<'inp>, Output = PckCert<Unverified>> {
    fn build_input(&'inp self, encrypted_ppid: Option<&'inp EncPpid>, pce_id: &'inp PceId, cpu_svn: &'inp CpuSvn, pce_isvsvn: PceIsvsvn, qe_id: Option<&'inp QeId>) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

pub struct PckCrlIn {
    api_version: PcsVersion,
}

impl WithApiVersion for PckCrlIn {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub trait PckCrlService<'inp> : ProvisioningServiceApi<'inp, Input = PckCrlIn, Output = PckCrl> {
    fn build_input(&'inp self) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

pub struct QeIdIn {
    pub api_version: PcsVersion,
}

impl WithApiVersion for QeIdIn {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub trait QeIdService<'inp> : ProvisioningServiceApi<'inp, Input = QeIdIn, Output = QeIdentitySigned> {
    fn build_input(&'inp self) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}


pub struct TcbInfoIn<'i> {
    pub(crate) api_version: PcsVersion,
    pub(crate) fmspc: &'i Vec<u8>,
}

impl WithApiVersion for TcbInfoIn<'_> {
    fn api_version(&self) -> PcsVersion {
        self.api_version
    }
}

pub trait TcbInfoService<'inp> : ProvisioningServiceApi<'inp, Input = TcbInfoIn<'inp>, Output = TcbInfo> {
    fn build_input(&'inp self, fmspc: &'inp Vec<u8>) -> <Self as ProvisioningServiceApi<'inp>>::Input;
}

#[derive(Default)]
pub struct ClientBuilder {
    retry_timeout: Option<Duration>,
}

impl ClientBuilder {
    pub(crate) fn new() -> Self {
        ClientBuilder::default()
    }

    pub(crate) fn set_retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.retry_timeout = Some(retry_timeout);
        self
    }

    pub(crate) fn build<PSS, PS, PC, QS, TS, F>(self, pckcerts_service: PSS, pckcert_service: PS, pckcrl_service: PC, qeid_service: QS, tcbinfo_service: TS, fetcher: F) -> Client<F>
    where
    PSS: for<'a> PckCertsService<'a> + Sync + Send + 'static,
    PS: for<'a> PckCertService<'a> + Sync + Send + 'static,
    PC: for<'a> PckCrlService<'a> + Sync + Send + 'static,
    QS: for<'a> QeIdService<'a> + Sync + Send + 'static,
    TS: for<'a> TcbInfoService<'a> + Sync + Send + 'static,
    F: for<'a> Fetcher<'a>,
    {
        Client::new(pckcerts_service, pckcert_service, pckcrl_service, qeid_service, tcbinfo_service, fetcher, self.retry_timeout)
    }
}

struct Service<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> {
    service: Box<T>,
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> Service<T> {
    pub fn new(service: Box<T>) -> Self {
        Self {
            service,
        }
    }
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> Service<T> {
    pub(crate) fn service(&self) -> &T {
        &self.service
    }

    fn call_service<'a, F: Fetcher<'a>>(&'a self, fetcher: &'a F, input: &<T as ProvisioningServiceApi<'a>>::Input) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
        let (url, headers) = <T as ProvisioningServiceApi<'a>>::build_request(&self.service(), input)?;
        let req = fetcher.build_request(&url, headers)?;
        let api_version = input.api_version();

        let (status_code, resp) = fetcher.send(req)?;
        <T as ProvisioningServiceApi<'a>>::validate_response(self.service(), status_code)?;
        let (response_body, response_headers) = fetcher.parse_response(resp)?;
        <T as ProvisioningServiceApi<'a>>::parse_response(self.service(), response_body, response_headers, api_version)
    }
}

struct BackoffService<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> {
    service: Service<T>,
    retry_timeout: Option<Duration>,
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> BackoffService<T> {
    pub fn new(service: Service<T>, retry_timeout: Option<Duration>) -> Self {
        Self {
            service,
            retry_timeout
        }
    }
}

impl<T: for<'a> ProvisioningServiceApi<'a> + Sync + ?Sized> BackoffService<T> {
    const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(2);
    const RETRY_INTERVAL_MULTIPLIER: f64 = 2.0;

    pub(crate) fn service(&self) -> &T {
        &self.service.service()
    }

    pub fn call_service<'a, F: Fetcher<'a>>(&'a self, fetcher: &'a F, input: &<T as ProvisioningServiceApi<'a>>::Input) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
        if let Some(retry_timeout) = self.retry_timeout {
            let op = || {
                match self.service.call_service::<F>(fetcher, input) {
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
                }
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

struct CachedService<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized> {
    service: BackoffService<T>,
    cache: Mutex<LruCache<String, (O, SystemTime)>>,
}

impl<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized> CachedService<O, T> {
    pub fn new(service: BackoffService<T>) -> Self {
        Self {
            service,
            cache: Mutex::new(LruCache::new(5)),
        }
    }
}

impl<O: Clone, T: for<'a> ProvisioningServiceApi<'a, Output = O> + Sync + ?Sized> CachedService<O, T> {
    const CACHE_SHELFTIME: Duration = Duration::from_secs(120);

    pub(crate) fn service(&self) -> &T {
        &self.service.service()
    }

    // Raoul: This is a generic function that will call individual Rest APIs of the PCS service.
    pub fn call_service<'a, F: Fetcher<'a>>(&'a self, fetcher: &'a F, input: &<T as ProvisioningServiceApi<'a>>::Input) -> Result<<T as ProvisioningServiceApi<'a>>::Output, Error> {
        let key = input.as_key(); // Raoul: Turns the input into a key
        let mut cache = self.cache.lock().unwrap();
        if let Some((value, time)) = cache.get_mut(&key) { // Raoul: Check whether the result is in the cache
            if Self::CACHE_SHELFTIME < time.elapsed().unwrap_or(Duration::MAX) {
                cache.remove(&key);
            } else {
                return Ok(value.to_owned());
            }
        }
        let value = self.service.call_service::<F>(fetcher, input)?; // Raoul: Actually do the REST API call
        cache.insert(key, (value.clone(), SystemTime::now()));
        Ok(value)
    }
}

trait CacheKey {
    fn as_key(&self) -> String {
        String::new() // Raoul: This is the default implementation for the trait. But it's wrong; for a specific type that represents input, we need to turn it into a key that can be used by the caching service. You should remove the body of this function.
    }
}

impl CacheKey for QeIdIn {
    fn as_key(&self) -> String {
        // TO DO: Is this where we contact the CacheKey service?Implementation for generating a key
        // Raoul: It's the other way around, see comments above
        self.as_key()
    }
}

impl<'i> CacheKey for PckCrlIn {
    fn as_key(&self) -> String {
        // TO DO: Is this where we contact the CacheKey service?Implementation for generating a key
        self.as_key()
    }
}

impl<'i> CacheKey for TcbInfoIn<'i> {
    fn as_key(&self) -> String {
        // TO DO: Is this where we contact the CacheKey service?Implementation for generating a key
        self.as_key()
    }
}

impl<'i> CacheKey for PckCertIn<'i> {
    fn as_key(&self) -> String {
        // TO DO: Is this where we contact the CacheKey service?Implementation for generating a key
        self.as_key()
    }
}

impl<'i> CacheKey for PckCertsIn<'i> {
    fn as_key(&self) -> String {
        // TO DO: Is this where we contact the CacheKey service?Implementation for generating a key
        self.as_key()
    }
}

pub struct Client<F: for<'a> Fetcher<'a>> {
    pckcerts_service: CachedService<PckCerts, dyn for<'a> PckCertsService<'a> + Sync + Send>,
    pckcert_service: CachedService<PckCert<Unverified>, dyn for<'a> PckCertService<'a> + Sync + Send>,
    pckcrl_service: CachedService<PckCrl, dyn for<'a> PckCrlService<'a> + Sync + Send>,
    qeid_service: CachedService<QeIdentitySigned, dyn for<'a> QeIdService<'a> + Sync + Send>,
    tcbinfo_service: CachedService<TcbInfo, dyn for<'a> TcbInfoService<'a> + Sync + Send>,
    fetcher: F,
}

impl<F: for<'a> Fetcher<'a>> Client<F> {
    fn new<PSS, PS, PC, QS, TS>(pckcerts_service: PSS, pckcert_service: PS, pckcrl_service: PC, qeid_service: QS, tcbinfo_service: TS, fetcher: F,retry_timeout: Option<Duration>) -> Client<F>
    where
    PSS: for<'a> PckCertsService<'a> + Sync + Send + 'static,
    PS: for<'a> PckCertService<'a> + Sync + Send + 'static,
    PC: for<'a> PckCrlService<'a> + Sync + Send + 'static,
    QS: for<'a> QeIdService<'a> + Sync + Send + 'static,
    TS: for<'a> TcbInfoService<'a> + Sync + Send + 'static,
    {
        Client {
            pckcerts_service: CachedService::new(BackoffService::new(Service::new(Box::new(pckcerts_service)), retry_timeout.clone())),
            pckcert_service: CachedService::new(BackoffService::new(Service::new(Box::new(pckcert_service)), retry_timeout.clone())),
            pckcrl_service: CachedService::new(BackoffService::new(Service::new(Box::new(pckcrl_service)), retry_timeout.clone())),
            qeid_service: CachedService::new(BackoffService::new(Service::new(Box::new(qeid_service)), retry_timeout.clone())),
            tcbinfo_service: CachedService::new(BackoffService::new(Service::new(Box::new(tcbinfo_service)), retry_timeout.clone())),
            fetcher,
        }
    }
}

pub trait ProvisioningClient {
    fn pckcerts(&self, enc_ppid: &EncPpid, pce_id: PceId) -> Result<PckCerts, Error>;

    fn pckcert(&self, encrypted_ppid: Option<&EncPpid>, pce_id: &PceId, cpu_svn: &CpuSvn, pce_isvsvn: PceIsvsvn, qe_id: Option<&QeId>) -> Result<PckCert<Unverified>, Error>;

    fn tcbinfo(&self, fmspc: &Vec<u8>) -> Result<TcbInfo, Error>;

    fn pckcrl(&self) -> Result<PckCrl, Error>;

    fn qe_identity(&self) -> Result<QeIdentitySigned, Error>;
}

impl<F: for<'a> Fetcher<'a>> ProvisioningClient for Client<F> {
    fn pckcerts(&self, encrypted_ppid: &EncPpid, pce_id: PceId) -> Result<PckCerts, Error> {
        let input = self.pckcerts_service.service().build_input(encrypted_ppid, pce_id);
        self.pckcerts_service.call_service(&self.fetcher, &input)
    }

    fn pckcert(&self, encrypted_ppid: Option<&EncPpid>, pce_id: &PceId, cpu_svn: &CpuSvn, pce_isvsvn: PceIsvsvn, qe_id: Option<&QeId>) -> Result<PckCert<Unverified>, Error> {
        let input = self.pckcert_service.service().build_input(encrypted_ppid, pce_id, cpu_svn, pce_isvsvn, qe_id);
        self.pckcert_service.call_service(&self.fetcher, &input)
    }

    fn tcbinfo(&self, fmspc: &Vec<u8>) -> Result<TcbInfo, Error> {
        let input = self.tcbinfo_service.service().build_input(fmspc);
        self.tcbinfo_service.call_service(&self.fetcher, &input)
    }

    fn pckcrl(&self) -> Result<PckCrl, Error> {
        let input = self.pckcrl_service.service().build_input();
        self.pckcrl_service.call_service(&self.fetcher, &input)
    }

    fn qe_identity(&self) -> Result<QeIdentitySigned, Error> {
        let input = self.qeid_service.service().build_input();
        self.qeid_service.call_service(&self.fetcher, &input)
    }
}

pub trait Fetcher<'req> {
    type Request;
    type Response;

    fn build_request(&'req self, url: &String, headers: Vec<(String, String)>) -> Result<Self::Request, Error>;
    fn send(&'req self, request: Self::Request) -> Result<(StatusCode, Self::Response), Error>;
    fn parse_response(&'req self, response: Self::Response) -> Result<(String, Vec<(String, String)>), Error>;
}

#[cfg(feature = "reqwest")]
impl<'req> Fetcher<'req> for ReqwestClient {
    type Request = reqwest::blocking::RequestBuilder;
    type Response = ReqwestResponse;

    fn build_request(&'req self, url: &String, headers: Vec<(String, String)>) -> Result<Self::Request, Error> {
        let url = reqwest::Url::parse(url).map_err(|e| e.to_string())?;

        let mut result = self.get(url);

        for (name, value) in headers {
            result = result.header(name, value);
        }

        Ok(result)
    }

    fn send(&'req self, request: Self::Request) -> Result<(StatusCode, Self::Response), Error> {
        let response = request.send().map_err(|e| e.to_string())?;
        let status_code = StatusCode::try_from(response.status().as_u16()).map_err(|e| e.to_string())?;

        Ok((status_code, response))
    }

    fn parse_response(&'req self, mut response: Self::Response) -> Result<(String, Vec<(String, String)>), Error> {
        let mut body = Vec::new();
        response.read_to_end(&mut body)
            .map_err(|e| Error::ReadResponseError(format!("Error while trying to read response body. Error: {}", e).into()))?;

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
    type Input: 'inp + WithApiVersion + CacheKey;
    type Output;

    fn build_request(&'inp self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error>;
    fn validate_response(&'inp self, code: StatusCode) -> Result<(), Error>;
    fn parse_response(&'inp self, response_body: String, response_headers: Vec<(String, String)>, api_version: PcsVersion) -> Result<Self::Output, Error>;
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
