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
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::time::Duration;

use pcs::{
    CpuSvn, DcapArtifactIssuer, EncPpid, Fmspc, PceId, PceIsvsvn, PckCert, PckCerts, PckCrl, PckID, QeId, QeIdentitySigned, RawTcbEvaluationDataNumbers, TcbComponentType, TcbInfo, Unverified, platform
};
use rustc_serialize::hex::FromHex;

use super::common::*;
use super::{
    Client, ClientBuilder, Fetcher, PckCertIn, PckCrlIn, PcsVersion,
    ProvisioningServiceApi, StatusCode,
};
use crate::{Error, ProvisioningClient};
use crate::provisioning_client::{BackoffService, CachedService, PckCertService};

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

    pub fn build<F: for<'a> Fetcher<'a>>(&self, fetcher: F) -> PCCSClient<F> {

        let client = self.client_builder
            .build(&self.base_url,
                self.api_version,
                fetcher);
        PCCSClient {
            pckcert_service: CachedService::new(
                BackoffService::new(
                    self.client_builder.retry_timeout.clone(),
                ),
                self.client_builder.cache_capacity.clone(),
                self.client_builder.cache_shelf_time.clone(),
            ),
            pckcrl_service: CachedService::new(
                BackoffService::new(
                    self.client_builder.retry_timeout.clone(),
                ),
                self.client_builder.cache_capacity.clone(),
                self.client_builder.cache_shelf_time.clone(),
            ),
            client
        }
    }
}

pub struct PCCSClient<F: for<'a> Fetcher<'a>> {
    pckcert_service: CachedService<PckCertService>,
    pckcrl_service: CachedService<PckCrlService>,
    client: Client<F>,
}

impl<F: for<'a> Fetcher<'a>> PCCSClient<F> {
    fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
        let get_and_collect = |collection: &mut BTreeMap<([u8; 16], u16), PckCert<Unverified>>, cpu_svn: &[u8; 16], pce_svn: u16| -> Result<PckCert<Unverified>, Error> {
            let pck_cert = self.pckcert(
                Some(&pck_id.enc_ppid),
                &pck_id.pce_id,
                cpu_svn,
                pce_svn,
                &pck_id.qe_id,
            )?;

            // Getting PCK cert using CPUSVN from PCKID
            let ptcb = pck_cert.platform_tcb()?;
            collection.insert((ptcb.cpusvn, ptcb.tcb_components.pce_svn()), pck_cert.clone());
            Ok(pck_cert)
        };

        // Use BTreeMap to have an ordered PckCerts at the end
        let mut pckcerts_map = BTreeMap::new();

        // 1. Use PCK ID to get best available PCK Cert
        let pck_cert = get_and_collect(&mut pckcerts_map, &pck_id.cpu_svn, pck_id.pce_isvsvn)?;

        // 2. Getting PCK cert using CPUSVN all 1's
        let _ign_err = get_and_collect(&mut pckcerts_map, &[u8::MAX; 16], pck_id.pce_isvsvn);

        let fmspc = pck_cert.sgx_extension()?.fmspc;
        let tcb_info = self.sgx_tcbinfo(&fmspc, None)?;
        let tcb_data = tcb_info.data()?;
        for (cpu_svn, pce_isvsvn) in tcb_data.iter_tcb_components() {
            // 3. Get PCK based on TCB levels
            let _ = get_and_collect(&mut pckcerts_map, &cpu_svn, pce_isvsvn)?;

            // 4. If late loaded microcode version is higher than early loaded microcode,
            //    also try with highest microcode version of both components. We found cases where
            //    fetching the PCK Cert that exactly matched the TCB level, did not result in a PCK
            //    Cert for that level
            let early_ucode_idx = tcb_data.tcb_component_index(TcbComponentType::EarlyMicrocodeUpdate);
            let late_ucode_idx = tcb_data.tcb_component_index(TcbComponentType::LateMicrocodeUpdate);
            if let (Some(early_ucode_idx), Some(late_ucode_idx)) = (early_ucode_idx, late_ucode_idx) {
                let early_ucode = cpu_svn[early_ucode_idx];
                let late_ucode = cpu_svn[late_ucode_idx];
                if early_ucode < late_ucode {
                    let mut cpu_svn = cpu_svn.clone();
                    cpu_svn[early_ucode_idx] = late_ucode;
                    let _ign_err = get_and_collect(&mut pckcerts_map, &cpu_svn, pce_isvsvn);
                }
            }
        }

        // BTreeMap by default is Ascending
        let pck_certs: Vec<_> = pckcerts_map.into_iter().rev().map(|(_, v)| v).collect();
        pck_certs
            .try_into()
            .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))
    }

    fn pckcert(
        &self,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: &QeId,
    ) -> Result<PckCert<Unverified>, Error> {
        let input = PckCertIn { encrypted_ppid, pce_id, cpu_svn, pce_isvsvn, qe_id: Some(&qe_id), api_version: self.client.api_version, api_key: &None };
        self.pckcert_service.call_service(&self.client.fetcher, &self.client.base_url, &input)
    }

    
}

impl<F: for<'a> Fetcher<'a>> ProvisioningClient for PCCSClient<F> {
    fn pckcert(
        &self,
        api_key: &Option<String>,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: Option<&QeId>,
    ) -> Result<PckCert<Unverified>, Error> {
        self.client.pckcert(api_key, encrypted_ppid, pce_id, cpu_svn, pce_isvsvn, qe_id)
    }

    fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
        self.client.pckcerts(pck_id)
    }

    fn pckcrl(&self, ca: DcapArtifactIssuer) -> Result<PckCrl<Unverified>, Error> {
        let input = PckCrlIn { api_version: self.client.api_version, ca };
        self.pckcrl_service.call_service(&self.client.fetcher, &self.client.base_url, &input)
    }

    fn qe_identity(&self, evaluation_data_number: Option<u16>) -> Result<QeIdentitySigned, Error> {
        self.client.qe_identity(evaluation_data_number)
    }

    fn sgx_tcbinfo(&self, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::SGX>, Error> {
        self.client.sgx_tcbinfo(fmspc, evaluation_data_number)
    }

    fn tdx_tcbinfo(&self, fmspc: &Fmspc, evaluation_data_number: Option<u16>) -> Result<TcbInfo<platform::TDX>, Error> {
        self.client.tdx_tcbinfo(fmspc, evaluation_data_number)
    }

    fn sgx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::SGX>, Error> {
        self.client.sgx_tcb_evaluation_data_numbers()
    }

    fn tdx_tcb_evaluation_data_numbers(&self) -> Result<RawTcbEvaluationDataNumbers<platform::TDX>, Error> {
        self.client.tdx_tcb_evaluation_data_numbers()
    }
}

struct PckCrlService;
impl ProvisioningServiceApi for PckCrlService {
    type Input<'a> = PckCrlIn;
    type Output = PckCrl<Unverified>;
    
    fn build_request(
        base_url: &str,
        input: &Self::Input<'_>,
    ) -> Result<(String, Vec<(String, String)>), Error> {
        crate::provisioning_client::PckCrlService::build_request(base_url, input)
    }
    
    fn validate_response(code: StatusCode) -> Result<(), Error> {
        crate::provisioning_client::PckCrlService::validate_response(code)
    }

    fn parse_response(
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
        EnclaveIdentity, Fmspc, PckID, RawTcbEvaluationDataNumbers, TcbEvaluationDataNumbers, WriteOptionsBuilder, platform
    };

    use crate::pccs::PCCSClient;
    use crate::provisioning_client::{
        test_helpers, DcapArtifactIssuer, Error, PccsProvisioningClientBuilder, PcsVersion,
        ProvisioningClient, StatusCode,
    };
    use crate::{PckCertIn, PckCrlIn, QeIdIn, TcbInfoIn, reqwest_client_insecure_tls};

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

    fn make_client(api_version: PcsVersion) -> PCCSClient<reqwest::blocking::Client> {
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
                        &pckid.qe_id,
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
                        &pckid.qe_id,
                    )
                    .unwrap();

                let pck = pck.verify(&root_cas, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.pckcert_service.cache.lock().unwrap();

                    assert!(cache.len() > 0);

                    let (cached_pck, _) = {
                        let mut hasher = DefaultHasher::new();
                        let input = PckCertIn { encrypted_ppid: Some(&pckid.enc_ppid), pce_id: &pckid.pce_id, cpu_svn: &pckid.cpu_svn, pce_isvsvn: pckid.pce_isvsvn, qe_id: Some(&pckid.qe_id), api_version, api_key: &None};
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
                        &pckid.qe_id,
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
                let pckcerts = client.pckcerts(&pckid).unwrap();
                println!("Found {} PCK certs.", pckcerts.as_pck_certs().len());

                let tcb_info = client.sgx_tcbinfo(&pckcerts.fmspc().unwrap(), None).unwrap();
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
                    &pckid.qe_id,
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
                let pckcerts = client.pckcerts(&pckid).unwrap();

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
                .pckcerts(&pckid)
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
                let pckcerts = client.pckcerts(&pckid).unwrap();
                let fmspc = pckcerts.fmspc().unwrap();
                let tcb_info = client.sgx_tcbinfo(&fmspc, None).unwrap();

                // The cache should be populated after initial service call
                {
                    let mut cache = client.client.sgx_tcbinfo_service.cache.lock().unwrap();

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
                let mut cache = client.client.qeid_service.cache.lock().unwrap();

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
