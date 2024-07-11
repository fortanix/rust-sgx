//! Interface to the Intel DCAP attestation API
//! Origins:
//!   - https://api.portal.trustedservices.intel.com/provisioning-certification
//!   - https://download.01.org/intel-sgx/dcap-1.1/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf

use percent_encoding::percent_decode;
use pcs::{CpuSvn, EncPpid, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl, QeId, QeIdentitySigned, TcbInfo, Unverified};
use pkix::pem::PemBlock;
use rustc_serialize::hex::ToHex;
use std::time::Duration;

use super::{Fetcher, PckCertIn, PckCertsIn, PckCertService, PckCertsService, PckCrlIn, PckCrlService, ProvisioningServiceApi, QeIdIn, QeIdService, StatusCode, TcbInfoIn, TcbInfoService};
use crate::provisioning_client::{Client, ClientBuilder, PcsVersion};
use crate::Error;

pub struct IntelProvisioningClientBuilder {
    api_key: Option<String>,
    api_version: PcsVersion,
    client_builder: ClientBuilder,
}

impl IntelProvisioningClientBuilder {
    pub fn new(api_version: PcsVersion) -> Self {
        Self {
            api_version,
            api_key: None,
            client_builder: ClientBuilder::new(),
        }
    }

    pub fn set_api_key(&mut self, api_key: String) -> &mut Self {
        self.api_key = Some(api_key);
        self
    }

    pub fn set_retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.client_builder = self.client_builder.set_retry_timeout(retry_timeout);
        self
    }

    pub fn build<F: for<'a> Fetcher<'a>>(self, fetcher: F) -> Client<F> {
        let pck_certs = PckCertsApi::new(self.api_version.clone(), self.api_key.clone());
        let pck_cert = PckCertApi::new(self.api_version.clone(), self.api_key.clone());
        let pck_crl = PckCrlApi::new(self.api_version.clone());
        let qeid = QeIdApi::new(self.api_version.clone());
        let tcbinfo = TcbInfoApi::new(self.api_version.clone());
        self.client_builder.build(pck_certs, pck_cert, pck_crl, qeid, tcbinfo, fetcher)
    }
}

pub struct PckCertsApi {
    api_key: Option<String>,
    api_version: PcsVersion,
}

impl PckCertsApi {
    pub(crate) fn new(api_version: PcsVersion, api_key: Option<String>) -> PckCertsApi {
        PckCertsApi {
            api_version,
            api_key,
        }
    }
}

impl<'inp> PckCertsService<'inp> for PckCertsApi {
    fn build_input(&'inp self, enc_ppid: &'inp EncPpid, pce_id: PceId) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCertsIn {
            enc_ppid,
            pce_id,
            api_key: &self.api_key,
            api_version: self.api_version.clone(),
        }
    }
}

impl<'inp> PckCertService<'inp> for PckCertApi {
    fn build_input(&'inp self, encrypted_ppid: Option<&'inp EncPpid>, pce_id: &'inp PceId, cpu_svn: &'inp CpuSvn, pce_isvsvn: PceIsvsvn, qe_id: Option<&'inp QeId>) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCertIn {
            encrypted_ppid,
            pce_id,
            cpu_svn,
            pce_isvsvn,
            qe_id,
            api_key: &self.api_key,
            api_version: self.api_version,
        }
    }
}

/// Implementation of pckcerts
/// https://api.portal.trustedservices.intel.com/documentation#pcs-certificates-v4
impl<'inp> ProvisioningServiceApi<'inp> for PckCertsApi {
    type Input = PckCertsIn<'inp>;
    type Output = PckCerts;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input.enc_ppid.to_hex();
        let pceid = input.pce_id.to_le_bytes().to_hex();
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v{api_version}/pckcerts?encrypted_ppid={encrypted_ppid}&pceid={pceid}",
        );
        let headers = if let Some(api_key) = &input.api_key {
            vec![("Ocp-Apim-Subscription-Key".to_owned(), api_key.to_string())]
        } else {
            Vec::new()
        };
        Ok((url, headers))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(status_code, "Cannot find the requested certificate")),
            StatusCode::TooManyRequests => Err(Error::PCSError(status_code, "Too many requests")),
            StatusCode::InternalServerError => {
                Err(Error::PCSError(status_code, "PCS suffered from an internal server error"))
            }
            StatusCode::ServiceUnavailable => {
                Err(Error::PCSError(status_code, "PCS is temporarily unavailable"))
            }
            _ => Err(Error::PCSError(status_code, "Unexpected response from PCS server")),
        }
    }

    fn parse_response(&self, response_body: String, response_headers: Vec<(String, String)>, _api_version: PcsVersion) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, "SGX-PCK-Certificate-Issuer-Chain")?;
        PckCerts::parse(&response_body, ca_chain).map_err(|e| Error::OfflineAttestationError(e))
    }
}

pub struct PckCertApi {
    api_key: Option<String>,
    api_version: PcsVersion,
}

impl PckCertApi {
    pub(crate) fn new(api_version: PcsVersion, api_key: Option<String>) -> PckCertApi {
        PckCertApi {
            api_version,
            api_key,
        }
    }
}

/// Implementation of pckcert
/// https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-certificate-v4
impl<'inp> ProvisioningServiceApi<'inp> for PckCertApi {
    type Input = PckCertIn<'inp>;
    type Output = PckCert<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input.encrypted_ppid.ok_or(Error::NoEncPPID).map(|e_ppid| e_ppid.to_hex())?;
        let cpusvn = input.cpu_svn.to_hex();
        let pcesvn = input.pce_isvsvn.to_le_bytes().to_hex();
        let pceid = input.pce_id.to_le_bytes().to_hex();
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v{api_version}/pckcert?encrypted_ppid={encrypted_ppid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}"
        );
        let headers = if let Some(api_key) = input.api_key {
            vec![("Ocp-Apim-Subscription-Key".to_owned(), api_key.to_string())]
        } else {
            Vec::new()
        };
        Ok((url, headers))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(status_code, "Cannot find the requested certificate")),
            StatusCode::TooManyRequests => Err(Error::PCSError(status_code, "Too many requests")),
            StatusCode::InternalServerError => {
                Err(Error::PCSError(status_code, "PCS suffered from an internal server error"))
            }
            StatusCode::ServiceUnavailable => {
                Err(Error::PCSError(status_code, "PCS is temporarily unavailable"))
            }
            _ => Err(Error::PCSError(status_code, "Unexpected response from PCS server")),
        }
    }

    fn parse_response(&self, response_body: String, response_headers: Vec<(String, String)>, _api_version: PcsVersion) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, "SGX-PCK-Certificate-Issuer-Chain")?;
        Ok(PckCert::new(response_body, ca_chain))
    }
}

pub struct PckCrlApi {
    api_version: PcsVersion,
}

impl PckCrlApi {
    pub fn new(api_version: PcsVersion) -> Self {
        PckCrlApi {
            api_version,
        }
    }
}

impl<'inp> PckCrlService<'inp> for PckCrlApi {
    fn build_input(&'inp self) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCrlIn {
            api_version: self.api_version.clone(),
        }
    }
}

/// Implementation of pckcrl
/// See: https://api.portal.trustedservices.intel.com/documentation#pcs-revocation-v4
impl<'inp> ProvisioningServiceApi<'inp> for PckCrlApi {
    type Input = PckCrlIn;
    type Output = PckCrl;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v{}/pckcrl?ca=processor&encoding=pem",
            input.api_version as u8
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::InternalServerError => {
                Err(Error::PCSError(status_code, "PCS suffered from an internal server error"))
            }
            StatusCode::ServiceUnavailable => {
                Err(Error::PCSError(status_code, "PCS is temporarily unavailable"))
            }
            __ => Err(Error::PCSError(status_code, "Unexpected response from PCS server")),
        }
    }

    fn parse_response(&self, response_body: String, response_headers: Vec<(String, String)>, _api_version: PcsVersion) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, "SGX-PCK-CRL-Issuer-Chain")?;
        let crl = PckCrl::new(response_body, ca_chain)?;
        Ok(crl)
    }
}

pub struct TcbInfoApi {
    api_version: PcsVersion,
}

impl TcbInfoApi {
    pub fn new(api_version: PcsVersion) -> Self {
        TcbInfoApi {
            api_version,
        }
    }
}

impl<'inp> TcbInfoService<'inp> for TcbInfoApi {
    fn build_input(&'inp self, fmspc: &'inp Vec<u8>) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        TcbInfoIn {
            api_version: self.api_version.clone(),
            fmspc,
        }
    }
}

// Implementation of Get TCB Info
// https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4
impl<'inp> ProvisioningServiceApi<'inp> for TcbInfoApi {
    type Input = TcbInfoIn<'inp>;
    type Output = TcbInfo;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let fmspc = input.fmspc.to_hex();
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v{}/tcb?fmspc={fmspc}",
            api_version
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(status_code, "QE identity Cannot be found")),
            StatusCode::InternalServerError => {
                Err(Error::PCSError(status_code, "PCS suffered from an internal server error"))
            }
            StatusCode::ServiceUnavailable => {
                Err(Error::PCSError(status_code, "PCS is temporarily unavailable"))
            }
            __ => Err(Error::PCSError(status_code, "Unexpected response from PCS server")),
        }
    }

    fn parse_response(&self, response_body: String, response_headers: Vec<(String, String)>, api_version: PcsVersion) -> Result<Self::Output, Error> {
        let key = match api_version {
            PcsVersion::V3 => "SGX-TCB-Info-Issuer-Chain",
            PcsVersion::V4 => "TCB-Info-Issuer-Chain",
        };
        let ca_chain = parse_issuer_header(&response_headers, key)?;
        let tcb_info = TcbInfo::parse(&response_body, ca_chain)?;
        Ok(tcb_info)
    }
}

pub struct QeIdApi {
    api_version: PcsVersion,
}

impl QeIdApi {
    pub fn new(api_version: PcsVersion) -> Self {
        QeIdApi {
            api_version,
        }
    }
}

impl<'inp> QeIdService<'inp> for QeIdApi {
    fn build_input(&'inp self) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        QeIdIn {
            api_version: self.api_version.clone(),
        }
    }
}

/// Implementation of qe/identity
/// https://api.portal.trustedservices.intel.com/documentation#pcs-certificates-v://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v4
impl<'inp> ProvisioningServiceApi<'inp> for QeIdApi {
    type Input = QeIdIn;
    type Output = QeIdentitySigned;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let url = format!(
            "https://api.trustedservices.intel.com/sgx/certification/v{api_version}/qe/identity",
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => Err(Error::PCSError(status_code, "Invalid parameter")),
            StatusCode::Unauthorized => Err(Error::PCSError(
                status_code,
                "Failed to authenticate or authorize the request (check your PCS key)",
            )),
            StatusCode::NotFound => Err(Error::PCSError(status_code, "QE identity Cannot be found")),
            StatusCode::InternalServerError => {
                Err(Error::PCSError(status_code, "PCS suffered from an internal server error"))
            }
            StatusCode::ServiceUnavailable => {
                Err(Error::PCSError(status_code, "PCS is temporarily unavailable"))
            }
            __ => Err(Error::PCSError(status_code, "Unexpected response from PCS server")),
        }
    }

    fn parse_response(&self, response_body: String, response_headers: Vec<(String, String)>, _api_version: PcsVersion) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, "SGX-Enclave-Identity-Issuer-Chain")?;
        let id = QeIdentitySigned::parse(&response_body, ca_chain)?;
        Ok(id)
    }
}

/// Returns the certificate chain starting from the leaf CA
fn parse_issuer_header(headers: &Vec<(String, String)>, header: &'static str) -> Result<Vec<String>, Error> {
    let certchain = headers
        .iter()
        .find_map(|(key, value)| {
            if key.to_lowercase() == header.to_lowercase() {
                Some(value)
            } else {
                None
            }
        })
        .ok_or(Error::HeaderMissing(header))?;
    let certchain = percent_decode(certchain.as_bytes())
        .decode_utf8()
        .map_err(|e| Error::HeaderDecodeError(e))?;
    let mut chain: Vec<String> = vec![];
    for cert in PemBlock::new(certchain.as_bytes()) {
        let cert = String::from_utf8(cert.to_vec())
            .map_err(|_| Error::CertificateParseError("Cert could not be decoded into utf8"))?;
        chain.push(cert);
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use pcs::PckID;

    use crate::reqwest_client;
    use crate::provisioning_client::{
        test_helpers, IntelProvisioningClientBuilder, PcsVersion, ProvisioningClient
    };

    const PCS_API_KEY: &str = "<redacted>"; // Primary API key of raoul.strackx@fortanix.com
    const PCKID_TEST_FILE: &str = "./tests/data/pckid_retrieval.csv";
    const OUTPUT_TEST_DIR: &str = "./tests/data/";
    const TIME_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

    #[test]
    pub fn pcks() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                intel_builder.set_api_key(PCS_API_KEY.to_string());
            }
            let client = intel_builder.build(reqwest_client());
            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path()).unwrap().iter() {
                let pcks = client.pckcerts(&pckid.enc_ppid, pckid.pce_id.clone()).unwrap();
                assert_eq!(
                    test_helpers::get_cert_subject(pcks.ca_chain().last().unwrap()),
                    "Intel SGX Root CA"
                );
                pcks.fmspc().unwrap();
                pcks.store(OUTPUT_TEST_DIR, pckid.qe_id.as_slice()).unwrap();
            }
        }
    }

    #[test]
    pub fn pck() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                intel_builder.set_api_key(PCS_API_KEY.to_string());
            }
            let client = intel_builder.build(reqwest_client());
            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path()).unwrap().iter() {
                let pck = client.pckcert(Some(&pckid.enc_ppid), &pckid.pce_id, &pckid.cpu_svn, pckid.pce_isvsvn, None)
                    .unwrap();
                assert_eq!(
                    test_helpers::get_cert_subject(pck.ca_chain().last().unwrap()),
                    "Intel SGX Root CA"
                );
            }
        }
    }

    #[test]
    pub fn tcb_info() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                intel_builder.set_api_key(PCS_API_KEY.to_string());
            }
            let client = intel_builder.build(reqwest_client());
            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path()).unwrap().iter() {
                let pckcerts = client.pckcerts(&pckid.enc_ppid, pckid.pce_id.clone()).unwrap();
                assert!(client
                    .tcbinfo(&pckcerts.fmspc().unwrap())
                    .and_then(|tcb| { Ok(tcb.store(OUTPUT_TEST_DIR).unwrap()) })
                    .is_ok());
            }
        }
    }

    #[test]
    pub fn pckcrl() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                intel_builder.set_api_key(PCS_API_KEY.to_string());
            }
            let client = intel_builder.build(reqwest_client());
            assert!(client
                .pckcrl()
                .and_then(|crl| { Ok(crl.write_to_file(OUTPUT_TEST_DIR).unwrap()) })
                .is_ok());
        }
    }

    #[test]
    pub fn qe_identity() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                intel_builder.set_api_key(PCS_API_KEY.to_string());
            }
            let client = intel_builder.build(reqwest_client());
            let qe_id = client.qe_identity();
            assert!(qe_id.is_ok());
            assert!(qe_id.unwrap().write_to_file(OUTPUT_TEST_DIR).is_ok());
        }
    }
}
