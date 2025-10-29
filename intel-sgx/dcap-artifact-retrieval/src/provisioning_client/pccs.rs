/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Interface to the Intel SGX Provisioning Certificate Caching Service (PCCS).
//!
//! Reference:
//! <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf>

use std::borrow::Cow;
use std::time::Duration;

use pcs::{
    CpuSvn, DcapArtifactIssuer, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCrl, QeId, QeIdentitySigned, TcbInfo,
    Unverified,
};
use rustc_serialize::hex::{FromHex, ToHex};

use super::common::*;
use super::{
    Client, ClientBuilder, Fetcher, PckCertIn, PckCertService, PckCrlIn, PckCrlService, PcsVersion,
    ProvisioningServiceApi, QeIdIn, QeIdService, StatusCode, TcbInfoIn, TcbInfoService,
};
use super::intel::TcbEvaluationDataNumbersApi;
use crate::Error;

pub struct PccsProvisioningClientBuilder {
    base_url: Cow<'static, str>,
    api_version: PcsVersion,
    client_builder: ClientBuilder,
}

impl PccsProvisioningClientBuilder {
    pub fn new<T: Into<Cow<'static, str>>>(api_version: PcsVersion, base_url: T) -> Self {
        Self {
            base_url: base_url.into(),
            api_version,
            client_builder: ClientBuilder::new(),
        }
    }

    pub fn set_retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.client_builder = self.client_builder.set_retry_timeout(retry_timeout);
        self
    }

    pub fn build<F: for<'a> Fetcher<'a>>(self, fetcher: F) -> Client<F> {
        let pck_certs = PckCertsApiNotSupported;
        let pck_cert = PckCertApi::new(self.base_url.clone(), self.api_version);
        let pck_crl = PckCrlApi::new(self.base_url.clone(), self.api_version);
        let qeid = QeIdApi::new(self.base_url.clone(), self.api_version);
        let tcbinfo = TcbInfoApi::new(self.base_url.clone(), self.api_version);
        let evaluation_data_numbers = TcbEvaluationDataNumbersApi::new(self.base_url.clone());
        self.client_builder
            .build(pck_certs, pck_cert, pck_crl, qeid, tcbinfo, evaluation_data_numbers, fetcher)
    }
}

pub struct PckCertApi {
    base_url: Cow<'static, str>,
    api_version: PcsVersion,
}

impl PckCertApi {
    pub(crate) fn new(base_url: Cow<'static, str>, api_version: PcsVersion) -> PckCertApi {
        PckCertApi {
            base_url,
            api_version,
        }
    }
}

impl<'inp> PckCertService<'inp> for PckCertApi {
    fn build_input(
        &'inp self,
        encrypted_ppid: Option<&'inp EncPpid>,
        pce_id: &'inp PceId,
        cpu_svn: &'inp CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&'inp QeId>,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCertIn {
            encrypted_ppid,
            pce_id,
            cpu_svn,
            pce_isvsvn,
            qe_id,
            api_key: &None,
            api_version: self.api_version,
        }
    }
}

/// Implementation of Get PCK Certificate API (section 3.1 in the [reference]).
///
/// [reference]: <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf>
impl<'inp> ProvisioningServiceApi<'inp> for PckCertApi {
    type Input = PckCertIn<'inp>;
    type Output = PckCert<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input
            .encrypted_ppid
            .ok_or(Error::NoEncPPID)
            .map(|e_ppid| e_ppid.to_hex())?;

        let cpu_svn = input.cpu_svn.to_hex();
        let pce_isvsvn = input.pce_isvsvn.to_le_bytes().to_hex();
        let pce_id = input.pce_id.to_le_bytes().to_hex();
        let qe_id = input
            .qe_id
            .ok_or(Error::NoQeID)
            .map(|qe_id| qe_id.to_hex())?;

        let url = format!(
            "{}/sgx/certification/v{}/pckcert?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}&qeid={}",
            self.base_url, api_version, encrypted_ppid, cpu_svn, pce_isvsvn, pce_id, qe_id,
        );
        let headers = Vec::new();
        Ok((url, headers))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => {
                Err(Error::PCSError(status_code, "Invalid request parameters"))
            }
            StatusCode::NotFound => Err(Error::PCSError(
                status_code,
                "No cache data for this platform",
            )),
            StatusCode::NonStandard461 => Err(Error::PCSError(
                status_code,
                "The platform was not found in the cache",
            )),
            StatusCode::NonStandard462 => Err(Error::PCSError(
                status_code,
                "Certificates are not available for certain TCBs",
            )),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCCS suffered from an internal server error",
            )),
            StatusCode::BadGateway => Err(Error::PCSError(
                status_code,
                "Unable to retrieve the collateral from the Intel SGX PCS",
            )),
            _ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCCS server",
            )),
        }
    }

    fn parse_response(
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CERTIFICATE_ISSUER_CHAIN_HEADER)?;
        Ok(PckCert::new(response_body, ca_chain))
    }
}

pub struct PckCrlApi {
    base_url: Cow<'static, str>,
    api_version: PcsVersion,
}

impl PckCrlApi {
    pub fn new(base_url: Cow<'static, str>, api_version: PcsVersion) -> Self {
        PckCrlApi {
            base_url,
            api_version,
        }
    }
}

impl<'inp> PckCrlService<'inp> for PckCrlApi {
    fn build_input(&'inp self, ca: DcapArtifactIssuer) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCrlIn {
            api_version: self.api_version,
            ca,
        }
    }
}

/// Implementation of Get PCK Cert CRL API (section 3.2 of [reference]).
///
/// [reference]: <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf>
impl<'inp> ProvisioningServiceApi<'inp> for PckCrlApi {
    type Input = PckCrlIn;
    type Output = PckCrl<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let ca = match input.ca {
            DcapArtifactIssuer::PCKProcessorCA => "processor",
            DcapArtifactIssuer::PCKPlatformCA => "platform",
            DcapArtifactIssuer::SGXRootCA => {
                return Err(Error::PCSError(StatusCode::BadRequest, "Invalid ca parameter"));
            },
        };
        let url = format!(
            "{}/sgx/certification/v{}/pckcrl?ca={}",
            self.base_url, input.api_version as u8, ca
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => {
                Err(Error::PCSError(status_code, "Invalid request parameters"))
            }
            StatusCode::NotFound => Err(Error::PCSError(status_code, "PCK CRL cannot be found")),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCCS suffered from an internal server error",
            )),
            StatusCode::BadGateway => Err(Error::PCSError(
                status_code,
                "Unable to retrieve the collateral from the Intel SGX PCS",
            )),
            _ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCCS server",
            )),
        }
    }

    fn parse_response(
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CRL_ISSUER_CHAIN_HEADER)?;
        let pem_crl = pkix::pem::der_to_pem(
            &response_body.from_hex().map_err(|e| {
                Error::ReadResponseError(
                    format!("failed to parse response body as hex-encoded DER: {}", e).into(),
                )
            })?,
            pkix::pem::PEM_CRL,
        );
        Ok(PckCrl::new(pem_crl, ca_chain)?)
    }
}

pub struct TcbInfoApi {
    base_url: Cow<'static, str>,
    api_version: PcsVersion,
}

impl TcbInfoApi {
    pub fn new(base_url: Cow<'static, str>, api_version: PcsVersion) -> Self {
        TcbInfoApi {
            base_url,
            api_version,
        }
    }
}

impl<'inp> TcbInfoService<'inp> for TcbInfoApi {
    fn build_input(
        &'inp self,
        fmspc: &'inp Fmspc,
        tcb_evaluation_data_number: Option<u16>,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        TcbInfoIn {
            api_version: self.api_version,
            fmspc,
            tcb_evaluation_data_number,
        }
    }
}

/// Implementation of Get TCB Info API (section 3.3 of [reference]).
///
/// [reference]: <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf>
impl<'inp> ProvisioningServiceApi<'inp> for TcbInfoApi {
    type Input = TcbInfoIn<'inp>;
    type Output = TcbInfo;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let fmspc = input.fmspc.as_bytes().to_hex();
        let url = if let Some(evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/sgx/certification/v{}/tcb?fmspc={}&tcbEvaluationDataNumber={}",
                self.base_url, api_version, fmspc, evaluation_data_number)
        } else {
            format!(
                "{}/sgx/certification/v{}/tcb?fmspc={}&update=early",
                self.base_url, api_version, fmspc,
            )
        };
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::BadRequest => {
                Err(Error::PCSError(status_code, "Invalid request parameters"))
            }
            StatusCode::NotFound => Err(Error::PCSError(
                status_code,
                "TCB information for provided FMSPC cannot be found",
            )),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCCS suffered from an internal server error",
            )),
            StatusCode::BadGateway => Err(Error::PCSError(
                status_code,
                "Unable to retrieve the collateral from the Intel SGX PCS",
            )),
            _ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCCS server",
            )),
        }
    }

    fn parse_response(
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let key = match api_version {
            PcsVersion::V3 => TCB_INFO_ISSUER_CHAIN_HEADER_V3,
            PcsVersion::V4 => TCB_INFO_ISSUER_CHAIN_HEADER_V4,
        };
        let ca_chain = parse_issuer_header(&response_headers, key)?;
        Ok(TcbInfo::parse(&response_body, ca_chain)?)
    }
}

pub struct QeIdApi {
    base_url: Cow<'static, str>,
    api_version: PcsVersion,
}

impl QeIdApi {
    pub fn new(base_url: Cow<'static, str>, api_version: PcsVersion) -> Self {
        QeIdApi {
            base_url,
            api_version,
        }
    }
}

impl<'inp> QeIdService<'inp> for QeIdApi {
    fn build_input(&'inp self, tcb_evaluation_data_number: Option<u16>) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        QeIdIn {
            api_version: self.api_version,
            tcb_evaluation_data_number,
        }
    }
}

/// Implementation of Get Intel's QE Identity API (section 3.4 of [reference]).
///
/// [reference]: <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf>
impl<'inp> ProvisioningServiceApi<'inp> for QeIdApi {
    type Input = QeIdIn;
    type Output = QeIdentitySigned;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let url = if let Some(tcb_evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/sgx/certification/v{}/qe/identity?tcbEvaluationDataNumber={}",
                self.base_url, api_version, tcb_evaluation_data_number
            )
        } else {
            format!(
                "{}/sgx/certification/v{}/qe/identity?update=early",
                self.base_url, api_version,
            )
        };
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
        match &status_code {
            StatusCode::Ok => Ok(()),
            StatusCode::NotFound => Err(Error::PCSError(
                status_code,
                "QE identity information cannot be found",
            )),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCCS suffered from an internal server error",
            )),
            StatusCode::BadGateway => Err(Error::PCSError(
                status_code,
                "Unable to retrieve the collateral from the Intel SGX PCS",
            )),
            _ => Err(Error::PCSError(
                status_code,
                "Unexpected response from PCCS server",
            )),
        }
    }

    fn parse_response(
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, ENCLAVE_ID_ISSUER_CHAIN_HEADER)?;
        let id = QeIdentitySigned::parse(&response_body, ca_chain)?;
        Ok(id)
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use std::convert::TryFrom;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;

    use pcs::{
        EnclaveIdentity, Fmspc, PckID, Platform, RawTcbEvaluationDataNumbers,
        TcbEvaluationDataNumbers,
    };

    use super::Client;
    use crate::provisioning_client::{
        test_helpers, DcapArtifactIssuer, PccsProvisioningClientBuilder, PcsVersion,
        ProvisioningClient,
    };
    use crate::{reqwest_client_insecure_tls, ReqwestClient};

    const PCKID_TEST_FILE: &str = "./tests/data/pckid_retrieval.csv";
    const OUTPUT_TEST_DIR: &str = "./tests/data/";
    const TIME_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

    static PCCS_URL: OnceLock<String> = OnceLock::new();

    fn pccs_url_from_env() -> String {
        let url = std::env::var("PCCS_URL").unwrap_or(String::from("https://pccs.fortanix.com"));
        assert!(
            !url.is_empty(),
            "Empty string in environment variable: PCCS_URL"
        );
        url
    }

    fn make_client(api_version: PcsVersion) -> Client<ReqwestClient> {
        let url = &*PCCS_URL.get_or_init(pccs_url_from_env);
        PccsProvisioningClientBuilder::new(api_version, url)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client_insecure_tls())
    }

    #[test]
    pub fn pck() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pck = client
                    .pckcert(
                        Some(&pckid.enc_ppid),
                        &pckid.pce_id,
                        &pckid.cpu_svn,
                        pckid.pce_isvsvn,
                        Some(&pckid.qe_id),
                    )
                    .unwrap();

                assert_eq!(
                    test_helpers::get_cert_subject(pck.ca_chain().last().unwrap()),
                    "Intel SGX Root CA"
                );
            }
        }
    }

    #[test]
    pub fn pck_cached() {
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pck = client
                    .pckcert(
                        Some(&pckid.enc_ppid),
                        &pckid.pce_id,
                        &pckid.cpu_svn,
                        pckid.pce_isvsvn,
                        Some(&pckid.qe_id),
                    )
                    .unwrap();

                let pck = pck.verify(&root_cas, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.pckcert_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_pck, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = client.pckcert_service.pcs_service().build_input(
                            Some(&pckid.enc_ppid),
                            &pckid.pce_id,
                            &pckid.cpu_svn,
                            pckid.pce_isvsvn,
                            Some(&pckid.qe_id),
                        );
                        input.hash(&mut hasher);

                        cache
                            .get_mut(&hasher.finish())
                            .expect("Can't find key in cache")
                            .to_owned()
                    };

                    assert_eq!(
                        pck.fmspc().unwrap(),
                        cached_pck
                            .clone()
                            .verify(&root_cas, None)
                            .unwrap()
                            .fmspc()
                            .unwrap()
                    );
                    assert_eq!(pck.ca_chain(), cached_pck.ca_chain());
                }

                // Second service call should return value from cache
                let pck_from_service = client
                    .pckcert(
                        Some(&pckid.enc_ppid),
                        &pckid.pce_id,
                        &pckid.cpu_svn,
                        pckid.pce_isvsvn,
                        Some(&pckid.qe_id),
                    )
                    .unwrap();

                assert_eq!(
                    pck.fmspc().unwrap(),
                    pck_from_service
                        .clone()
                        .verify(&root_cas, None)
                        .unwrap()
                        .fmspc()
                        .unwrap()
                );
                assert_eq!(pck.ca_chain(), pck_from_service.ca_chain());
            }
        }
    }

    #[test]
    pub fn test_pckcerts_with_fallback() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client.pckcerts_with_fallback(&pckid).unwrap();
                println!("Found {} PCK certs.", pckcerts.as_pck_certs().len());

                let tcb_info = client.tcbinfo(&pckcerts.fmspc().unwrap(), None).unwrap();
                let tcb_data = tcb_info.data().unwrap();

                let selected = pckcerts
                    .select_pck(&tcb_data, &pckid.cpu_svn, pckid.pce_isvsvn, pckid.pce_id)
                    .unwrap();

                let pck = client
                    .pckcert(
                    Some(&pckid.enc_ppid),
                    &pckid.pce_id,
                    &pckid.cpu_svn,
                    pckid.pce_isvsvn,
                    Some(&pckid.qe_id),
                    )
                    .unwrap();

                assert_eq!(
                    format!("{:?}", selected.sgx_extension().unwrap()),
                    format!("{:?}", pck.sgx_extension().unwrap())
                );
            }
        }
    }

    #[test]
    pub fn tcb_info() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client.pckcerts_with_fallback(&pckid).unwrap();

                assert!(client
                    .tcbinfo(&pckcerts.fmspc().unwrap(), None)
                    .and_then(|tcb| { Ok(tcb.store(OUTPUT_TEST_DIR).unwrap()) })
                    .is_ok());
            }
        }
    }

    #[test]
    pub fn tcb_info_with_evaluation_data_number() {
        let client = make_client(PcsVersion::V4);
        for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
            .unwrap()
            .iter()
        {
            let pckcerts = client
                .pckcerts_with_fallback(&pckid)
                .unwrap();

            let fmspc = pckcerts.fmspc().unwrap();

            let evaluation_data_numbers = client
                .tcb_evaluation_data_numbers()
                .unwrap()
                .evaluation_data_numbers()
                .unwrap();

            for number in evaluation_data_numbers.numbers() {
                // TODO(#811): Since PCCS is cache service and not able to cache the
                // `Gone` response mentioned below from Intel PCS, We need to change
                // the test behavior to call TCB INFO API with update=standard to get the
                // smallest TcbEvaluationDataNumber that's still available.
                //
                // Here, we temporarily fix this be hardcoding.
                if number.number() < 17 {
                    continue;
                }
                let tcb = match client.tcbinfo(&fmspc, Some(number.number())) {
                    Ok(tcb) => tcb,
                    // API query with update="standard" will return QE Identity with TCB Evaluation Data Number M.
                    // A 410 Gone response is returned when the inputted TCB Evaluation Data Number is < M,
                    // so we ignore these TCB Evaluation Data Numbers.
                    Err(super::Error::PCSError(status_code, _)) if status_code == super::StatusCode::Gone => continue,
                    res @Err(_) => res.unwrap(),
                };
                tcb.store(OUTPUT_TEST_DIR).unwrap();
            }
        }
    }

    #[test]
    pub fn tcb_info_cached() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client.pckcerts_with_fallback(&pckid).unwrap();
                let fmspc = pckcerts.fmspc().unwrap();
                let tcb_info = client.tcbinfo(&fmspc, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.tcbinfo_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_tcb_info, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = client
                            .tcbinfo_service
                            .pcs_service()
                            .build_input(&fmspc, None);
                        input.hash(&mut hasher);

                        cache
                            .get_mut(&hasher.finish())
                            .expect("Can't find key in cache")
                            .to_owned()
                    };

                    assert_eq!(tcb_info, cached_tcb_info);
                }

                // Second service call should return value from cache
                let tcb_info_from_service = client.tcbinfo(&fmspc, None).unwrap();

                assert_eq!(tcb_info, tcb_info_from_service);
            }
        }
    }

    #[test]
    pub fn pckcrl() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);
            assert!(client
                .pckcrl(DcapArtifactIssuer::PCKProcessorCA)
                .and_then(|crl| Ok(crl.write_to_file(OUTPUT_TEST_DIR).unwrap()))
                .is_ok());
            assert!(client
                .pckcrl(DcapArtifactIssuer::PCKPlatformCA)
                .and_then(|crl| Ok(crl.write_to_file(OUTPUT_TEST_DIR).unwrap()))
                .is_ok());
        }
    }

    #[test]
    pub fn pckcrl_cached() {
        for ca in [
            DcapArtifactIssuer::PCKProcessorCA,
            DcapArtifactIssuer::PCKPlatformCA,
        ] {
            for api_version in [PcsVersion::V3, PcsVersion::V4] {
                let client = make_client(api_version);
                let pckcrl = client.pckcrl(ca).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.pckcrl_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_pckcrl, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = client.pckcrl_service.pcs_service().build_input(ca);
                        input.hash(&mut hasher);

                        cache
                            .get_mut(&hasher.finish())
                            .expect("Can't find key in cache")
                            .to_owned()
                    };

                    assert_eq!(pckcrl, cached_pckcrl);
                }

                // Second service call should return value from cache
                let pckcrl_from_service = client.pckcrl(ca).unwrap();

                assert_eq!(pckcrl, pckcrl_from_service);
            }
        }
    }

    #[test]
    pub fn qe_identity() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);
            let qe_id = client.qe_identity(None);
            assert!(qe_id.is_ok());
            assert!(qe_id.unwrap().write_to_file(OUTPUT_TEST_DIR).is_ok());
        }
    }

    #[test]
    pub fn qe_identity_cached() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);
            let qe_id = client.qe_identity(None).unwrap();

            // The cache should be populated after initial service call
            {
                let mut cache = client.qeid_service.cache.lock().unwrap();

                assert!(cache.len() > 0);

                let (cached_qeid, _) = {
                    let mut hasher = DefaultHasher::new();
                    let input = client.qeid_service.pcs_service().build_input(None);
                    input.hash(&mut hasher);

                    cache
                        .get_mut(&hasher.finish())
                        .expect("Can't find key in cache")
                        .to_owned()
                };

                assert_eq!(qe_id, cached_qeid);
            }

            // Second service call should return value from cache
            let qeid_from_service = client.qe_identity(None).unwrap();

            assert_eq!(qe_id, qeid_from_service);
        }
    }

    #[test]
    pub fn tcb_evaluation_data_numbers() {
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        let client = make_client(PcsVersion::V4);
        let eval_numbers = client.tcb_evaluation_data_numbers().unwrap();

        let eval_numbers2 = serde_json::ser::to_vec(&eval_numbers)
            .and_then(|v| serde_json::from_slice::<RawTcbEvaluationDataNumbers>(&v))
            .unwrap();
        assert_eq!(eval_numbers, eval_numbers2);

        let fmspc = Fmspc::try_from("90806f000000").unwrap();
        let eval_numbers: TcbEvaluationDataNumbers =
            eval_numbers.verify(&root_cas, Platform::SGX).unwrap();
        for number in eval_numbers.numbers().map(|n| n.number()) {
            // TODO(#811): Since PCCS is cache service and not able to cache the
            // `Gone` response mentioned below from Intel PCS, We need to change
            // the test behavior to call QE ID API with update=standard to get the
            // smallest TcbEvaluationDataNumber that's still available.
            //
            // Here, we temporarily fix this be hardcoding.
            if number < 17 {
                continue;
            }
            let qe_identity = match client.qe_identity(Some(number)) {
                Ok(id) => id,
                // API query with update="standard" will return QE Identity with TCB Evaluation Data Number M.
                // A 410 Gone response is returned when the inputted TCB Evaluation Data Number is < M,
                // so we ignore these TCB Evaluation Data Numbers.
                Err(super::Error::PCSError(status_code, _)) if status_code == super::StatusCode::Gone => continue,
                res @Err(_) => res.unwrap(),
            };
            let verified_qe_id = qe_identity
                .verify(&root_cas, EnclaveIdentity::QE)
                .unwrap();
            assert_eq!(verified_qe_id.tcb_evaluation_data_number(), u64::from(number));

            let tcb_info = client
                    .tcbinfo(&fmspc, Some(number))
                    .unwrap()
                    .verify(&root_cas, Platform::SGX, 2)
                    .unwrap();
            assert_eq!(tcb_info.tcb_evaluation_data_number(), u64::from(number));
        }
    }
}
