/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use pcs::{CpuSvn, EncPpid, PceId, PceIsvsvn, PckCert, PckCerts, PckID, QeId, TcbComponentType, Unverified, platform};
use rustc_serialize::hex::ToHex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::time::Duration;

use super::{
    Client, ClientBuilder, Fetcher, PcsVersion, ProvisioningServiceApi,
    StatusCode,
};
use crate::intel::IntelPCSClient;
use crate::provisioning_client::{BackoffService, CachedService, PcsService, QeIdService, TcbEvaluationDataNumbersService, TcbInfoService};
use crate::{Error, IntelProvisioningClientBuilder, WithApiVersion};

/// A Provisioning Certificate client builder for Azure. It is based on the internal logic of the Azure DCAP
/// provider. Only the PCK certificates are downloaded from Azure. For others Intel is contacted.
/// This is required because Azure by default provides an older `tcbinfo` with a `next_update`
/// field in the past (see PROD-5800).
/// For info on the Azure DCAP provider: <https://github.com/microsoft/Azure-DCAP-Client>
pub struct AzureProvisioningClientBuilder {
    api_version: PcsVersion,
    client_builder: IntelProvisioningClientBuilder,
}

impl AzureProvisioningClientBuilder {
    pub fn new(api_version: PcsVersion) -> Self {
        Self {
            api_version,
            client_builder: IntelProvisioningClientBuilder::new(api_version),
        }
    }

    pub fn set_retry_timeout(mut self, retry_timeout: Duration) -> Self {
        self.client_builder = self.client_builder.set_retry_timeout(retry_timeout);
        self
    }

    pub fn build<F: for<'a> Fetcher<'a>>(&self, fetcher: F) -> AzureClient<F> {
        let pckcert_service = PckCertService;
        let qeid = QeIdService;
        let sgx_tcbinfo = TcbInfoService::<platform::SGX> {_type: PhantomData};
        let tdx_tcbinfo = TcbInfoService::<platform::TDX> {_type: PhantomData};
        let sgx_evaluation_data_numbers = TcbEvaluationDataNumbersService::<platform::SGX> { _type: PhantomData };
        let tdx_evaluation_data_numbers = TcbEvaluationDataNumbersService::<platform::TDX> { _type: PhantomData };

        let client = self.client_builder.build(
            fetcher,
        );
        AzureClient {
            azure_base_url: PckCertApi::SECONDARY_CERT_URL.to_owned(),
            azure_client_id: PckCertApi::DEFAULT_CLIENT_ID.to_owned(),
            azure_api_id: PckCertApi::API_VERSION_07_2021.to_owned(),
            pckcert_service: CachedService::new(
                BackoffService::new(
                    PcsService::new(pckcert_service),
                    self.client_builder.client_builder.retry_timeout.clone(),
                ),
                self.client_builder.client_builder.cache_capacity.clone(),
                self.client_builder.client_builder.cache_shelf_time.clone(),
            ),
            client,
        }
    }
}

struct AzureClient<F: for<'b> Fetcher<'b>> {
    azure_base_url: String,
    azure_client_id: String,
    azure_api_id: String,
    pckcert_service: CachedService<PckCertService>,
    client: IntelPCSClient<F>,
}

impl<F: for<'a> Fetcher<'a>> AzureClient<F> {
    fn pckcert(
        &self,
        encrypted_ppid: Option<&EncPpid>,
        pce_id: &PceId,
        cpu_svn: &CpuSvn,
        pce_isvsvn: PceIsvsvn,
        qe_id: &QeId,
    ) -> Result<PckCert<Unverified>, Error> {
        let input = PckCertIn { encrypted_ppid, pce_id, cpu_svn, pce_isvsvn, qe_id: Some(&qe_id), api_version: self.client.client.api_version, api_key: &None, azure_client_id: &self.azure_client_id, azure_api_version: &self.azure_api_id };
        self.pckcert_service.call_service(&self.client.client.fetcher, &self.azure_base_url, &input)
    }

    fn pckcerts(&self, pck_id: &PckID) -> Result<PckCerts, Error> {
        // let input = PckCertsIn { api_version: self.client.api_version, pck_id: &pck_id };
        // self.pckcerts_service.call_service(&self.client.fetcher, &self.client.base_url, &input)

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
        let tcb_info = self.client.sgx_tcbinfo(&fmspc, None)?;
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
}

pub struct PckCertApi {
    api_version: PcsVersion,
}

impl PckCertApi {
    // Constants from the Azure DCAP client:
    // (host of primary URL is down)
    const SECONDARY_CERT_URL: &'static str = "https://global.acccache.azure.net/sgx/certification";
    const DEFAULT_CLIENT_ID: &'static str = "production_client";
    const API_VERSION_07_2021: &'static str = "2021-07-22-preview";
}

#[derive(Hash)]
struct PckCertIn<'a> {
    encrypted_ppid: Option<&'a EncPpid>,
    pce_id: &'a PceId,
    cpu_svn: &'a CpuSvn,
    pce_isvsvn: PceIsvsvn,
    qe_id: Option<&'a QeId>,
    api_version: PcsVersion,
    api_key: &'a Option<String>,
    azure_client_id: &'a str,
    azure_api_version: &'a str,
}

impl<'a> WithApiVersion for PckCertIn<'a> {
    fn api_version(&self) -> PcsVersion {
        PcsVersion::V4
    }
}

struct PckCertService;
impl ProvisioningServiceApi for PckCertService {
    type Input<'a> = PckCertIn<'a>;
    type Output = PckCert<Unverified>;

    fn build_request(&self, base_url: &str, input: &Self::Input<'_>) -> Result<(String, Vec<(String, String)>), Error> {
        // Re-implements `build_pck_cert_url` from Azure's DCAP Client
        // https://github.com/microsoft/Azure-DCAP-Client/blob/master/src/dcap_provider.cpp#L677
        // Constants from the Azure DCAP client:
        // (host of primary URL is down)
        let version = input.api_version as u8;
        let qeid =  input.qe_id.ok_or(Error::NoQeID)?.to_hex();
        let cpusvn = input.cpu_svn.to_hex();
        let pcesvn = input.pce_isvsvn.to_le_bytes().to_hex();
        let pceid = input.pce_id.to_le_bytes().to_hex();
        let clientid =  input.azure_client_id;
        let api_version = input.azure_api_version;
        let url = format!("{base_url}/v{version}/pckcert?qeid={qeid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}&clientid={clientid}&api-version={api_version}");
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
            StatusCode::NotFound => Err(Error::PCSError(
                status_code,
                "Cannot find the requested certificate",
            )),
            StatusCode::InternalServerError => Err(Error::PCSError(
                status_code,
                "PCS suffered from an internal server error",
            )),
            StatusCode::ServiceUnavailable => Err(Error::PCSError(
                status_code,
                "PCS is temporarily unavailable",
            )),
            StatusCode::Gone => Err(Error::PCSError(
                status_code,
                "Collateral is no longer available",
            )),
            _ => Err(Error::PCSError(
                status_code.clone(),
                "Unexpected response from PCS server",
            )),
        }
    }

    fn parse_response(
        &self,
        response_body: String,
        _response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<PckCert<Unverified>, Error> {
        #[derive(Deserialize)]
        struct AzurePckCertResp {
            #[serde(rename = "pckCert")]
            pck_cert: String,
            // Azure funny business: the `sgx-Pck-Certificate-Issuer-Chain` field is percent
            // encoded. The `pck_cert` field is not.
            #[serde(rename = "sgx-Pck-Certificate-Issuer-Chain")]
            cert_chain: String,
        }

        let AzurePckCertResp {
            pck_cert,
            cert_chain,
        } = serde_json::from_str(&response_body)
            .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))?;

        let cert_chain: Vec<String> = percent_encoding::percent_decode_str(&cert_chain)
            .decode_utf8()
            .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))?
            .split_inclusive("-----END CERTIFICATE-----\n")
            .map(|c| c.trim().to_string())
            .collect();
        Ok(PckCert::new(pck_cert, cert_chain))
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use assert_matches::assert_matches;
    use std::convert::TryFrom;
    use std::path::PathBuf;
    use std::time::Duration;

    use pcs::{Fmspc, PckID};

    use crate::provisioning_client::{
        test_helpers, AzureProvisioningClientBuilder, DcapArtifactIssuer, PcsVersion,
        ProvisioningClient,
    };
    use crate::{Error, StatusCode, reqwest_client};

    const PCKID_TEST_FILE: &str = "./tests/data/azure_icelake_pckid.csv";

    const TIME_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

    #[test]
    pub fn pcks_azure() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());
            let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
            let root_cas = [&root_ca[..]];

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pck = client
                    .pckcert(
                        None,
                        &pckid.pce_id,
                        &pckid.cpu_svn,
                        pckid.pce_isvsvn,
                        &pckid.qe_id
                    )
                    .unwrap();

                let pck = pck.verify(&root_cas, None).unwrap();
                assert_eq!(
                    test_helpers::get_cert_subject(&pck.ca_chain().last().unwrap()),
                    "Intel SGX Root CA"
                );
                assert_eq!(
                    test_helpers::get_cert_subject(&pck.pck_pem()),
                    "Intel SGX PCK Certificate"
                );

                let fmspc: Fmspc = pck.fmspc().unwrap();
                assert!(client.client.sgx_tcbinfo(&fmspc, None).is_ok());
            }
        }
    }

    #[test]
    pub fn pck_crl() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());
            assert!(client.client.pckcrl(DcapArtifactIssuer::PCKProcessorCA).is_ok());
            assert!(client.client.pckcrl(DcapArtifactIssuer::PCKPlatformCA).is_ok());
        }
    }

    #[test]
    pub fn qe_identity() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());
            assert!(client.client.qe_identity(None).is_ok());
        }
    }

    #[test]
    pub fn gone_artifacts() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());
            let fmspc = Fmspc::try_from("90806f000000").unwrap();
            assert_matches!(
                client.client.qe_identity(Some(15)),
                Err(Error::PCSError(StatusCode::Gone, _))
            );
            assert_matches!(
                client.client.sgx_tcbinfo(&fmspc, Some(15)),
                Err(Error::PCSError(StatusCode::Gone, _))
            );
        }
    }

    #[test]
    pub fn test_pckcerts_with_fallback() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());

            for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
                .unwrap()
                .iter()
            {
                let pckcerts = client.pckcerts(&pckid).unwrap();
                println!("Found {} PCK certs.", pckcerts.as_pck_certs().len());

                let tcb_info = client.client
                    .sgx_tcbinfo(&pckcerts.fmspc().unwrap(), None)
                    .unwrap();
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
    pub fn sgx_tcb_evaluation_data_numbers() {
        for api_version in [PcsVersion::V3, PcsVersion::V4] {
            let client = AzureProvisioningClientBuilder::new(api_version)
                .set_retry_timeout(TIME_RETRY_TIMEOUT)
                .build(reqwest_client());
            assert!(client.client.sgx_tcb_evaluation_data_numbers().is_ok());
        }
    }
}
