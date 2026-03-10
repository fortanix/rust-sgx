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
use std::marker::PhantomData;
use std::time::Duration;

use pcs::platform::SGX;
use pcs::{
    CpuSvn, DcapArtifactIssuer, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCrl, PlatformType, PlatformTypeForTcbInfo, QeId, QeIdentitySigned, TcbInfo, Unverified, platform
};
use rustc_serialize::hex::{FromHex, ToHex};

use super::common::*;
use super::{
    Client, ClientBuilder, Fetcher, PckCertIn, PckCertService, PckCrlIn, PckCrlService, PcsVersion,
    ProvisioningServiceApi, QeIdIn, QeIdService, StatusCode, TcbInfoIn, TcbInfoService,
};
use crate::{Error, PckCertsService};
use crate::provisioning_client::{PCSPckCrlService, TcbEvaluationDataNumbersService};

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

    pub fn build<F: for<'a> Fetcher<'a>, PC: PckCrlService>(self, fetcher: F) -> Client<F, PC> {
        let pck_certs = PckCertsService;
        let pck_cert = PckCertService;
        let pck_crl = PC::new();
        let qeid = QeIdService;
        let sgx_tcbinfo = TcbInfoService::<platform::SGX> {_type: PhantomData};
        let tdx_tcbinfo = TcbInfoService::<platform::TDX> {_type: PhantomData};
        let sgx_evaluation_data_numbers: TcbEvaluationDataNumbersService<SGX> = TcbEvaluationDataNumbersService::<platform::SGX> { _type: PhantomData };
        let tdx_evaluation_data_numbers = TcbEvaluationDataNumbersService::<platform::TDX> { _type: PhantomData };


        self.client_builder
            .build(&self.base_url, self.api_version, pck_certs, pck_cert, pck_crl, qeid, sgx_tcbinfo, tdx_tcbinfo, sgx_evaluation_data_numbers, tdx_evaluation_data_numbers, fetcher)
    }
}


pub struct PCCSPckCrlService {
    parent: PCSPckCrlService
}

impl PckCrlService for PCCSPckCrlService {
    fn build_input(&self, api_version: PcsVersion, ca: DcapArtifactIssuer) -> <Self as ProvisioningServiceApi>::Input<'_> {
        PckCrlIn { api_version, ca }
    }
    
    fn new() -> Self {
        Self { parent: PCSPckCrlService }
    }
}

impl ProvisioningServiceApi for PCCSPckCrlService {
    type Input<'a> = <PCSPckCrlService as ProvisioningServiceApi>::Input<'a>;
    type Output = <PCSPckCrlService as ProvisioningServiceApi>::Output;
    
    fn build_request(
        &self,
        base_url: &str,
        input: &Self::Input<'_>,
    ) -> Result<(String, Vec<(String, String)>), Error> {
        self.parent.build_request(base_url, input)
    }
    
    fn validate_response(&self, code: StatusCode) -> Result<(), Error> {
        self.parent.validate_response(code)
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


#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use assert_matches::assert_matches;
    use std::convert::TryFrom;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use std::time::Duration;

    use pcs::{
        EnclaveIdentity, Fmspc, PckCrl, PckID, RawTcbEvaluationDataNumbers, TcbEvaluationDataNumbers, WriteOptionsBuilder, platform
    };

    use super::Client;
    use crate::pccs::PCCSPckCrlService;
    use crate::provisioning_client::{
        test_helpers, DcapArtifactIssuer, Error, PccsProvisioningClientBuilder, PcsVersion,
        ProvisioningClient, StatusCode,
    };
    use crate::{PckCertIn, PckCrlIn, QeIdIn, ReqwestClient, TcbInfoIn, reqwest_client_insecure_tls};

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

    fn make_client(api_version: PcsVersion) -> Client<ReqwestClient, PCCSPckCrlService> {
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
                        &None,
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
                        &None,
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
                        let input = PckCertIn { encrypted_ppid: Some(&pckid.enc_ppid), pce_id: &pckid.pce_id, cpu_svn: &pckid.cpu_svn, pce_isvsvn: pckid.pce_isvsvn, qe_id: Some(&pckid.qe_id), api_version, api_key: &None };
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
                        &None,
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
                let pckcerts = client.pckcerts_with_fallback(&None, &pckid).unwrap();
                println!("Found {} PCK certs.", pckcerts.as_pck_certs().len());

                let tcb_info = client.sgx_tcbinfo(&pckcerts.fmspc().unwrap(), None).unwrap();
                let tcb_data = tcb_info.data().unwrap();

                let selected = pckcerts
                    .select_pck(&tcb_data, &pckid.cpu_svn, pckid.pce_isvsvn, pckid.pce_id)
                    .unwrap();

                let pck = client
                    .pckcert(
                        &None,
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
                let pckcerts = client.pckcerts_with_fallback(&None, &pckid).unwrap();

                assert!(client
                    .sgx_tcbinfo(&pckcerts.fmspc().unwrap(), None)
                    .and_then(|tcb| { Ok(tcb.write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build()).unwrap()) })
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
                .pckcerts_with_fallback(&None, &pckid)
                .unwrap();

            let fmspc = pckcerts.fmspc().unwrap();

            let evaluation_data_numbers = client
                .sgx_tcb_evaluation_data_numbers()
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
                if number.number() < 18 {
                    continue;
                }
                let tcb = match client.sgx_tcbinfo(&fmspc, Some(number.number())) {
                    Ok(tcb) => tcb,
                    // API query with update="standard" will return QE Identity with TCB Evaluation Data Number M.
                    // A 410 Gone response is returned when the inputted TCB Evaluation Data Number is < M,
                    // so we ignore these TCB Evaluation Data Numbers.
                    Err(super::Error::PCSError(status_code, _)) if status_code == super::StatusCode::Gone => continue,
                    res @Err(_) => res.unwrap(),
                };
                tcb.write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build()).unwrap();
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
                let pckcerts = client.pckcerts_with_fallback(&None, &pckid).unwrap();
                let fmspc = pckcerts.fmspc().unwrap();
                let tcb_info = client.sgx_tcbinfo(&fmspc, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.sgx_tcbinfo_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_tcb_info, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = TcbInfoIn{ api_version, fmspc: &fmspc, tcb_evaluation_data_number: None };
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
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = make_client(api_version);
            assert!(client
                .pckcrl(DcapArtifactIssuer::PCKProcessorCA)
                .and_then(|crl| Ok(crl.write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build()).unwrap()))
                .is_ok());
            assert!(client
                .pckcrl(DcapArtifactIssuer::PCKPlatformCA)
                .and_then(|crl| Ok(crl.write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build()).unwrap()))
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
                        let input = PckCrlIn { api_version, ca };
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
            assert!(qe_id.unwrap().write_to_file(OUTPUT_TEST_DIR, WriteOptionsBuilder::new().build()).is_ok());
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
                    let input = QeIdIn { api_version, tcb_evaluation_data_number: None };
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
            let client = make_client(api_version);
            let fmspc = Fmspc::try_from("90806f000000").unwrap();
            assert_matches!(client.qe_identity(Some(15)), Err(Error::PCSError(StatusCode::Gone, _)));
            assert_matches!(client.sgx_tcbinfo(&fmspc, Some(15)), Err(Error::PCSError(StatusCode::Gone, _)));
        }
    }

    #[test]
    pub fn tcb_evaluation_data_numbers() {
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        let client = make_client(PcsVersion::V4);
        let eval_numbers = client.sgx_tcb_evaluation_data_numbers().unwrap();

        let eval_numbers2 = serde_json::ser::to_vec(&eval_numbers)
            .and_then(|v| serde_json::from_slice::<RawTcbEvaluationDataNumbers<platform::SGX>>(&v))
            .unwrap();
        assert_eq!(eval_numbers, eval_numbers2);

        let fmspc = Fmspc::try_from("90806f000000").unwrap();
        let eval_numbers: TcbEvaluationDataNumbers<platform::SGX> =
            eval_numbers.verify(&root_cas).unwrap();
        for number in eval_numbers.numbers().map(|n| n.number()) {
            // TODO(#811): Since PCCS is cache service and not able to cache the
            // `Gone` response mentioned below from Intel PCS, We need to change
            // the test behavior to call QE ID API with update=standard to get the
            // smallest TcbEvaluationDataNumber that's still available.
            //
            // Here, we temporarily fix this be hardcoding.
            if number < 18 {
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
                    .sgx_tcbinfo(&fmspc, Some(number))
                    .unwrap()
                    .verify(&root_cas, 2)
                    .unwrap();
            assert_eq!(tcb_info.tcb_evaluation_data_number(), u64::from(number));
        }
    }
}
