/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Interface to the Intel DCAP attestation API.
//!
//! Origins:
//! - <https://api.portal.trustedservices.intel.com/provisioning-certification>
//! - <https://download.01.org/intel-sgx/dcap-1.1/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf>

use pcs::{
    CpuSvn, DcapArtifactIssuer, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl,
    PlatformType, PlatformTypeForTcbInfo, QeId, QeIdentitySigned, RawTcbEvaluationDataNumbers,
    TcbInfo, Unverified,
};
use rustc_serialize::hex::ToHex;
use std::borrow::Cow;
use std::marker::PhantomData;
use std::time::Duration;

use super::common::*;
use super::{
    Client, ClientBuilder, Fetcher, PckCertIn, PckCertService, PckCertsIn, PckCertsService,
    PckCrlIn, PckCrlService, PcsVersion, ProvisioningServiceApi, QeIdIn, QeIdService, StatusCode,
    TcbEvaluationDataNumbersIn, TcbEvaluationDataNumbersService, TcbInfoIn, TcbInfoService,
    WithApiVersion,
};
use crate::provisioning_client::PlatformApiTag;
use crate::Error;

pub(crate) const INTEL_BASE_URL: &'static str = "https://api.trustedservices.intel.com";
const SUBSCRIPTION_KEY_HEADER: &'static str = "Ocp-Apim-Subscription-Key";

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
        let sgx_tcbinfo = TcbInfoApi::new(self.api_version.clone());
        let tdx_tcbinfo = TcbInfoApi::new(self.api_version.clone());
        let sgx_evaluation_data_numbers = TcbEvaluationDataNumbersApi::new(INTEL_BASE_URL.into());
        let tdx_evaluation_data_numbers = TcbEvaluationDataNumbersApi::new(INTEL_BASE_URL.into());

        self.client_builder.build(
            pck_certs,
            pck_cert,
            pck_crl,
            qeid,
            sgx_tcbinfo,
            tdx_tcbinfo,
            sgx_evaluation_data_numbers,
            tdx_evaluation_data_numbers,
            fetcher,
        )
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
    fn build_input(
        &'inp self,
        enc_ppid: &'inp EncPpid,
        pce_id: PceId,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCertsIn {
            enc_ppid,
            pce_id,
            api_key: &self.api_key,
            api_version: self.api_version.clone(),
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
            api_key: &self.api_key,
            api_version: self.api_version,
        }
    }
}

/// Implementation of pckcerts
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-certificates-v4>
impl<'inp> ProvisioningServiceApi<'inp> for PckCertsApi {
    type Input = PckCertsIn<'inp>;
    type Output = PckCerts;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input.enc_ppid.to_hex();
        let pce_id = input.pce_id.to_le_bytes().to_hex();
        let url = format!(
            "{}/sgx/certification/v{}/pckcerts?encrypted_ppid={}&pceid={}",
            INTEL_BASE_URL, api_version, encrypted_ppid, pce_id,
        );
        let headers = if let Some(api_key) = &input.api_key {
            vec![(SUBSCRIPTION_KEY_HEADER.to_owned(), api_key.to_string())]
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
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CERTIFICATE_ISSUER_CHAIN_HEADER)?;
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
/// <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-certificate-v4>
impl<'inp> ProvisioningServiceApi<'inp> for PckCertApi {
    type Input = PckCertIn<'inp>;
    type Output = PckCert<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let encrypted_ppid = input
            .encrypted_ppid
            .ok_or(Error::NoEncPPID)
            .map(|e_ppid| e_ppid.to_hex())?;
        let cpusvn = input.cpu_svn.to_hex();
        let pce_isvsvn = input.pce_isvsvn.to_le_bytes().to_hex();
        let pce_id = input.pce_id.to_le_bytes().to_hex();
        let url = format!(
            "{}/sgx/certification/v{}/pckcert?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}",
            INTEL_BASE_URL, api_version, encrypted_ppid, cpusvn, pce_isvsvn, pce_id,
        );
        let headers = if let Some(api_key) = input.api_key {
            vec![(SUBSCRIPTION_KEY_HEADER.to_owned(), api_key.to_string())]
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
    api_version: PcsVersion,
}

impl PckCrlApi {
    pub fn new(api_version: PcsVersion) -> Self {
        PckCrlApi { api_version }
    }
}

impl<'inp> PckCrlService<'inp> for PckCrlApi {
    fn build_input(
        &'inp self,
        ca: DcapArtifactIssuer,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCrlIn {
            api_version: self.api_version.clone(),
            ca,
        }
    }
}

/// Implementation of pckcrl
/// See: <https://api.portal.trustedservices.intel.com/documentation#pcs-revocation-v4>
impl<'inp> ProvisioningServiceApi<'inp> for PckCrlApi {
    type Input = PckCrlIn;
    type Output = PckCrl<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
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
            INTEL_BASE_URL, input.api_version as u8, ca,
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
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain = parse_issuer_header(&response_headers, PCK_CRL_ISSUER_CHAIN_HEADER)?;
        let crl = PckCrl::new(response_body, ca_chain)?;
        Ok(crl)
    }
}

pub struct TcbInfoApi<T> {
    api_version: PcsVersion,
    _type: PhantomData<T>,
}

impl<T: PlatformType> TcbInfoApi<T> {
    pub fn new(api_version: PcsVersion) -> Self {
        TcbInfoApi {
            api_version,
            _type: PhantomData,
        }
    }
}

impl<'inp, T: PlatformTypeForTcbInfo + PlatformApiTag> TcbInfoService<'inp, T>
    for TcbInfoApi<T>
{
    fn build_input(
        &'inp self,
        fmspc: &'inp Fmspc,
        tcb_evaluation_data_number: Option<u16>,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        TcbInfoIn {
            api_version: self.api_version.clone(),
            fmspc,
            tcb_evaluation_data_number,
        }
    }
}

// Implementation of Get TCB Info
// <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>>
impl<'inp, T: PlatformTypeForTcbInfo + PlatformApiTag> ProvisioningServiceApi<'inp>
    for TcbInfoApi<T>
{
    type Input = TcbInfoIn<'inp>;
    type Output = TcbInfo<T>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let fmspc = input.fmspc.as_bytes().to_hex();
        let url = if let Some(evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/{}/certification/v{}/tcb?fmspc={}&tcbEvaluationDataNumber={}",
                INTEL_BASE_URL,
                T::tag(),
                api_version,
                fmspc,
                evaluation_data_number
            )
        } else {
            format!(
                "{}/{}/certification/v{}/tcb?fmspc={}&update=early",
                INTEL_BASE_URL,
                T::tag(),
                api_version,
                fmspc,
            )
        };
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
        let tcb_info = TcbInfo::parse(&response_body, ca_chain)?;
        Ok(tcb_info)
    }
}

pub struct QeIdApi {
    api_version: PcsVersion,
}

impl QeIdApi {
    pub fn new(api_version: PcsVersion) -> Self {
        QeIdApi { api_version }
    }
}

impl<'inp> QeIdService<'inp> for QeIdApi {
    fn build_input(
        &'inp self,
        tcb_evaluation_data_number: Option<u16>,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        QeIdIn {
            api_version: self.api_version.clone(),
            tcb_evaluation_data_number,
        }
    }
}

/// Implementation of qe/identity
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-certificates-v://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v4>
impl<'inp> ProvisioningServiceApi<'inp> for QeIdApi {
    type Input = QeIdIn;
    type Output = QeIdentitySigned;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let api_version = input.api_version as u8;
        let url = if let Some(tcb_evaluation_data_number) = input.tcb_evaluation_data_number {
            format!(
                "{}/sgx/certification/v{}/qe/identity?tcbEvaluationDataNumber={}",
                INTEL_BASE_URL, api_version, tcb_evaluation_data_number
            )
        } else {
            format!(
                "{}/sgx/certification/v{}/qe/identity?update=early",
                INTEL_BASE_URL, api_version,
            )
        };
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

pub struct TcbEvaluationDataNumbersApi<T: PlatformTypeForTcbInfo> {
    base_url: Cow<'static, str>,
    _platform: PhantomData<T>,
}

impl<T: PlatformTypeForTcbInfo> TcbEvaluationDataNumbersApi<T> {
    pub fn new(base_url: Cow<'static, str>) -> Self {
        TcbEvaluationDataNumbersApi {
            base_url,
            _platform: PhantomData,
        }
    }
}

impl<'inp, T: PlatformTypeForTcbInfo + PlatformApiTag> TcbEvaluationDataNumbersService<'inp, T>
    for TcbEvaluationDataNumbersApi<T>
{
    fn build_input(&self) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        TcbEvaluationDataNumbersIn
    }
}

/// Implementation of TCB Evaluation Data Numbers endpoint
/// <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-retrieve-tcbevalnumbers-v4>
impl<'inp, T: PlatformTypeForTcbInfo + PlatformApiTag> ProvisioningServiceApi<'inp>
    for TcbEvaluationDataNumbersApi<T>
{
    type Input = TcbEvaluationDataNumbersIn;
    type Output = RawTcbEvaluationDataNumbers<T>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        let url = format!(
            "{}/{}/certification/v{}/tcbevaluationdatanumbers",
            self.base_url,
            T::tag(),
            input.api_version() as u8,
        );
        Ok((url, Vec::new()))
    }

    fn validate_response(&self, status_code: StatusCode) -> Result<(), Error> {
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
        &self,
        response_body: String,
        response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        let ca_chain =
            parse_issuer_header(&response_headers, TCB_EVALUATION_DATA_NUMBERS_ISSUER_CHAIN)?;
        RawTcbEvaluationDataNumbers::parse(&response_body, ca_chain).map_err(|e| e.into())
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use assert_matches::assert_matches;
    use std::convert::TryFrom;
    use std::hash::Hash;
    use std::hash::Hasher;
    use std::path::PathBuf;
    use std::time::Duration;

    use pcs::platform;
    use pcs::PlatformTypeForTcbInfo;
    use pcs::{
        DcapArtifactIssuer, EnclaveIdentity, Fmspc, PckID, RawTcbEvaluationDataNumbers,
        WriteOptionsBuilder,
    };

    use crate::provisioning_client::{
        test_helpers, ProvisioningClientFuncSelector, IntelProvisioningClientBuilder, PcsVersion, ProvisioningClient,
    };
    use crate::{Error, reqwest_client, StatusCode};
    use std::hash::DefaultHasher;

    const PCKID_TEST_FILE: &str = "./tests/data/pckid_retrieval.csv";
    const OUTPUT_TEST_DIR: &str = "./tests/data/";
    const TIME_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

    fn pcs_api_key() -> Option<String> {
        let api_key_option = std::env::var("PCS_API_KEY").ok();
        if let Some(api_key) = api_key_option.as_ref() {
            assert!(!api_key.is_empty(), "Empty string in PCS_API_KEY");
        }
        api_key_option
    }

    #[test]
    pub fn pcks() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pcks = client
                    .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                    .unwrap();
                assert_eq!(
                    test_helpers::get_cert_subject(pcks.ca_chain().last().unwrap()),
                    "Intel SGX Root CA"
                );
                pcks.fmspc().unwrap();
                pcks.write_to_file(
                    OUTPUT_TEST_DIR,
                    pckid.qe_id.as_slice(),
                    WriteOptionsBuilder::new().build(),
                )
                .unwrap();
            }
        }
    }

    #[test]
    pub fn pcks_cached() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pcks = client
                    .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                    .unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.pckcerts_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_pcks, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = client
                            .pckcerts_service
                            .pcs_service()
                            .build_input(&pckid.enc_ppid, pckid.pce_id.clone());
                        input.hash(&mut hasher);

                        cache
                            .get_mut(&hasher.finish())
                            .expect("Can't find key in cache")
                            .to_owned()
                    };

                    assert_eq!(pcks.fmspc().unwrap(), cached_pcks.fmspc().unwrap());
                    assert_eq!(pcks, cached_pcks);
                }

                // Second service call should return value from cache
                let pcks_from_service = client
                    .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                    .unwrap();

                assert_eq!(pcks, pcks_from_service);
                assert_eq!(pcks.fmspc().unwrap(), pcks_from_service.fmspc().unwrap());
            }
        }
    }

    #[test]
    pub fn pck() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
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
                        None,
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
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
            let root_cas = [&root_ca[..]];
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
            let crl_processor = client
                .pckcrl(DcapArtifactIssuer::PCKProcessorCA)
                .unwrap()
                .crl_as_pem()
                .to_owned();
            let crl_platform = client
                .pckcrl(DcapArtifactIssuer::PCKPlatformCA)
                .unwrap()
                .crl_as_pem()
                .to_owned();
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
                        None,
                    )
                    .unwrap();
                let pck = pck
                    .clone()
                    .verify(&root_cas, Some(&crl_processor))
                    .or(pck.clone().verify(&root_cas, Some(&crl_platform)))
                    .unwrap();

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
                            None,
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
                        None,
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
    pub fn tcb_info() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client
                    .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                    .unwrap();
                assert!(client
                    .sgx_tcbinfo(&pckcerts.fmspc().unwrap(), None)
                    .and_then(|tcb| {
                        Ok(tcb
                            .write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build())
                            .unwrap())
                    })
                    .is_ok());
            }
        }
    }

    #[test]
    pub fn tcb_info_tdx() {
        let intel_builder = IntelProvisioningClientBuilder::new(PcsVersion::V4)
            .set_retry_timeout(TIME_RETRY_TIMEOUT);
        let client = intel_builder.build(reqwest_client());
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];

        // List of knowns FMSPCS that has valid TDX TCB
        let fmspcs = [
            Fmspc::try_from("00a06d080000").unwrap(),
            Fmspc::try_from("70a06d070000").unwrap(),
            Fmspc::try_from("00a06e050000").unwrap(),
            Fmspc::try_from("50806f000000").unwrap(),
            Fmspc::try_from("20a06e050000").unwrap(),
            Fmspc::try_from("10a06f010000").unwrap(),
            Fmspc::try_from("b0c06f000000").unwrap(),
            Fmspc::try_from("20a06f000000").unwrap(),
            Fmspc::try_from("60a06f000000").unwrap(),
            Fmspc::try_from("c0806f000000").unwrap(),
            Fmspc::try_from("20a06d080000").unwrap(),
            Fmspc::try_from("10a06d000000").unwrap(),
            Fmspc::try_from("00806f050000").unwrap(),
            Fmspc::try_from("90c06f000000").unwrap(),
        ];

        for item in fmspcs.iter() {
            let tdx_tcbinfo = client.tdx_tcbinfo(&item, None);
            println!("FMSPC: {} => {}", item.to_string(), tdx_tcbinfo.is_ok());
            assert!(tdx_tcbinfo.is_ok());

            let _ = tdx_tcbinfo.unwrap().verify(&root_cas, 2).unwrap();
        }
    }

    #[test]
    pub fn tcb_info_with_evaluation_data_number() {
        let intel_builder = IntelProvisioningClientBuilder::new(PcsVersion::V4)
            .set_retry_timeout(TIME_RETRY_TIMEOUT);
        let client = intel_builder.build(reqwest_client());
        for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
            .unwrap()
            .iter()
        {
            let pckcerts = client
                .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                .unwrap();
            let fmspc = pckcerts.fmspc().unwrap();

            let evaluation_data_numbers = client
                .sgx_tcb_evaluation_data_numbers()
                .unwrap()
                .evaluation_data_numbers()
                .unwrap();

            for number in evaluation_data_numbers.numbers() {
                let tcb = match client.sgx_tcbinfo(&fmspc, Some(number.number())) {
                    Ok(tcb) => tcb,
                    // API query with update="standard" will return QE Identity with TCB Evaluation Data Number M.
                    // A 410 Gone response is returned when the inputted TCB Evaluation Data Number is < M,
                    // so we ignore these TCB Evaluation Data Numbers.
                    Err(super::Error::PCSError(status_code, _))
                        if status_code == super::StatusCode::Gone =>
                    {
                        continue
                    }
                    res @ Err(_) => res.unwrap(),
                };
                tcb.write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build())
                    .unwrap();
            }
        }
    }

    #[test]
    pub fn tcb_info_cached() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client
                    .pckcerts(&pckid.enc_ppid, pckid.pce_id.clone())
                    .unwrap();
                let fmspc = pckcerts.fmspc().unwrap();
                let tcb_info = client.sgx_tcbinfo(&fmspc, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.sgx_tcbinfo_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_tcb_info, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = client
                            .sgx_tcbinfo_service
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
                let tcb_info_from_service = client.sgx_tcbinfo(&fmspc, None).unwrap();

                assert_eq!(tcb_info, tcb_info_from_service);
            }
        }
    }

    #[test]
    pub fn pckcrl() {
        for ca in [
            DcapArtifactIssuer::PCKProcessorCA,
            DcapArtifactIssuer::PCKPlatformCA,
        ] {
            for api_version in [PcsVersion::V3, PcsVersion::V4] {
                let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                    .set_retry_timeout(TIME_RETRY_TIMEOUT);
                if api_version == PcsVersion::V3 {
                    if let Some(pcs_api_key) = pcs_api_key() {
                        intel_builder.set_api_key(pcs_api_key);
                    } else {
                        // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                        // So we no longer force to test it.
                        continue;
                    }
                }
                let client = intel_builder.build(reqwest_client());
                assert!(client
                    .pckcrl(ca)
                    .and_then(|crl| {
                        Ok(crl
                            .write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build())
                            .unwrap())
                    })
                    .is_ok());
            }
        }
    }

    #[test]
    pub fn pckcrl_cached() {
        for ca in [
            DcapArtifactIssuer::PCKProcessorCA,
            DcapArtifactIssuer::PCKPlatformCA,
        ] {
            for api_version in [PcsVersion::V3, PcsVersion::V4] {
                let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                    .set_retry_timeout(TIME_RETRY_TIMEOUT);
                if api_version == PcsVersion::V3 {
                    if let Some(pcs_api_key) = pcs_api_key() {
                        intel_builder.set_api_key(pcs_api_key);
                    } else {
                        // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                        // So we no longer force to test it.
                        continue;
                    }
                }
                let client = intel_builder.build(reqwest_client());
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
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
            let qe_id = client.qe_identity(None).unwrap();
            assert!(qe_id
                .write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build())
                .is_ok());
        }
    }

    #[test]
    pub fn qe_identity_cached() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let mut intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            if api_version == PcsVersion::V3 {
                if let Some(pcs_api_key) = pcs_api_key() {
                    intel_builder.set_api_key(pcs_api_key);
                } else {
                    // Intel SGX PCS version 3 is scheduled to end of life not later than October 31, 2025.
                    // So we no longer force to test it.
                    continue;
                }
            }
            let client = intel_builder.build(reqwest_client());
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
    pub fn gone_artifacts() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let intel_builder = IntelProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT);
            let client = intel_builder.build(reqwest_client());
            let fmspc = Fmspc::try_from("90806f000000").unwrap();
            assert_matches!(client.qe_identity(Some(15)), Err(Error::PCSError(StatusCode::Gone, _)));
            assert_matches!(client.sgx_tcbinfo(&fmspc, Some(15)), Err(Error::PCSError(StatusCode::Gone, _)));
        }
    }

    fn tcb_evaluation_data_numbers_test_base<T: PartialEq>()
    where
        T: PlatformTypeForTcbInfo + ProvisioningClientFuncSelector + std::fmt::Debug,
    {
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        let intel_builder = IntelProvisioningClientBuilder::new(PcsVersion::V4)
            .set_retry_timeout(TIME_RETRY_TIMEOUT);
        let client = intel_builder.build(reqwest_client());
        let eval_numbers = T::get_tcb_evaluation_data_numbers(&client).unwrap();

        let eval_numbers2 = serde_json::ser::to_vec(&eval_numbers)
            .and_then(|v| serde_json::from_slice::<RawTcbEvaluationDataNumbers<T>>(&v))
            .unwrap();
        assert_eq!(eval_numbers, eval_numbers2);

        let fmspc = Fmspc::try_from("50806f000000").unwrap();
        let eval_numbers = eval_numbers.verify(&root_cas).unwrap();
        for number in eval_numbers.numbers().map(|n| n.number()) {
            let qe_identity = match client.qe_identity(Some(number)) {
                Ok(id) => id,
                // API query with update="standard" will return QE Identity with TCB Evaluation Data Number M.
                // A 410 Gone response is returned when the inputted TCB Evaluation Data Number is < M,
                // so we ignore these TCB Evaluation Data Numbers.
                Err(super::Error::PCSError(status_code, _))
                    if status_code == super::StatusCode::Gone =>
                {
                    continue
                }
                res @ Err(_) => res.unwrap(),
            };
            let verified_qe_id = qe_identity.verify(&root_cas, EnclaveIdentity::QE).unwrap();
            assert_eq!(
                verified_qe_id.tcb_evaluation_data_number(),
                u64::from(number)
            );

            let tcb_info = T::get_tcbinfo(&client, &fmspc, Some(number))
                .unwrap()
                .verify(&root_cas, 2)
                .unwrap();
            assert_eq!(tcb_info.tcb_evaluation_data_number(), u64::from(number));
        }
    }

    #[test]
    pub fn sgx_tcb_evaluation_data_numbers() {
        tcb_evaluation_data_numbers_test_base::<platform::SGX>()
    }

    #[test]
    pub fn tdx_tcb_evaluation_data_numbers() {
        tcb_evaluation_data_numbers_test_base::<platform::TDX>()
    }
}
