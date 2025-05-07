/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use pcs::{CpuSvn, EncPpid, PceId, PceIsvsvn, PckCert, QeId, Unverified};
use rustc_serialize::hex::ToHex;
use serde::Deserialize;
use std::time::Duration;

use super::common::PckCertsApiNotSupported;
use super::intel::{INTEL_BASE_URL, TcbEvaluationDataNumbersApi, PckCrlApi, QeIdApi, TcbInfoApi};
use super::{
    Client, ClientBuilder, Fetcher, PckCertIn, PckCertService, PcsVersion, ProvisioningServiceApi,
    StatusCode,
};
use crate::Error;

/// A Provisioning Certificate client builder for Azure. It is based on the internal logic of the Azure DCAP
/// provider. Only the PCK certificates are downloaded from Azure. For others Intel is contacted.
/// This is required because Azure by default provides an older `tcbinfo` with a `next_update`
/// field in the past (see PROD-5800).
/// For info on the Azure DCAP provider: <https://github.com/microsoft/Azure-DCAP-Client>
pub struct AzureProvisioningClientBuilder {
    api_version: PcsVersion,
    client_builder: ClientBuilder,
}

impl AzureProvisioningClientBuilder {
    pub fn new(api_version: PcsVersion) -> Self {
        Self {
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
        let pck_cert = PckCertApi::new(self.api_version.clone());
        let pck_crl = PckCrlApi::new(self.api_version.clone());
        let qeid = QeIdApi::new(self.api_version.clone());
        let tcbinfo = TcbInfoApi::new(self.api_version.clone());
        let evaluation_data_numbers = TcbEvaluationDataNumbersApi::new(INTEL_BASE_URL.into());
        self.client_builder
            .build(pck_certs, pck_cert, pck_crl, qeid, tcbinfo, evaluation_data_numbers, fetcher)
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

impl PckCertApi {
    pub(crate) fn new(api_version: PcsVersion) -> PckCertApi {
        PckCertApi { api_version }
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
            api_version: self.api_version,
            api_key: &None,
        }
    }
}

impl<'inp> ProvisioningServiceApi<'inp> for PckCertApi {
    type Input = PckCertIn<'inp>;
    type Output = PckCert<Unverified>;

    fn build_request(&self, input: &Self::Input) -> Result<(String, Vec<(String, String)>), Error> {
        // Re-implements `build_pck_cert_url` from Azure's DCAP Client
        // https://github.com/microsoft/Azure-DCAP-Client/blob/master/src/dcap_provider.cpp#L677
        fn build_pck_cert_url(
            pce_id: &PceId,
            cpu_svn: &CpuSvn,
            pce_isvsvn: PceIsvsvn,
            qe_id: &QeId,
            api_version: PcsVersion,
        ) -> String {
            // Constants from the Azure DCAP client:
            // (host of primary URL is down)
            let base_url = PckCertApi::SECONDARY_CERT_URL;
            let version = api_version as u8;
            let qeid = qe_id.to_hex();
            let cpusvn = cpu_svn.to_hex();
            let pcesvn = pce_isvsvn.to_le_bytes().to_hex();
            let pceid = pce_id.to_le_bytes().to_hex();
            let clientid = PckCertApi::DEFAULT_CLIENT_ID;
            let api_version = PckCertApi::API_VERSION_07_2021;
            format!("{base_url}/v{version}/pckcert?qeid={qeid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}&clientid={clientid}&api-version={api_version}")
        }

        let qe_id = input.qe_id.ok_or(Error::NoQeID)?;
        let url = build_pck_cert_url(
            input.pce_id,
            input.cpu_svn,
            input.pce_isvsvn,
            qe_id,
            input.api_version,
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
    use std::path::PathBuf;
    use std::time::Duration;

    use pcs::PckID;

    use crate::provisioning_client::{
        test_helpers, AzureProvisioningClientBuilder, PckCA, PcsVersion, ProvisioningClient,
    };
    use crate::reqwest_client;

    const PCKID_TEST_FILE: &str = "./tests/data/azure_icelake_pckid.csv";

    const TIME_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

    #[test]
    pub fn pcks_azure() {
        let client = AzureProvisioningClientBuilder::new(PcsVersion::V3)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client());
        let root_ca = include_bytes!("../../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];

        // TODO [EDP-105] Enable `PcsVersion::V4` tests
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
                    Some(&pckid.qe_id),
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

            let fmspc = pck.fmspc().unwrap();
            assert!(client.tcbinfo(&fmspc, None).is_ok());
        }
    }

    #[test]
    pub fn pck_crl() {
        let client = AzureProvisioningClientBuilder::new(PcsVersion::V3)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client());
        assert!(client.pckcrl(PckCA::Processor).is_ok());
        assert!(client.pckcrl(PckCA::Platform).is_ok());
    }

    #[test]
    pub fn qe_identity() {
        let client = AzureProvisioningClientBuilder::new(PcsVersion::V3)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client());
        assert!(client.qe_identity(None).is_ok());
    }

    #[test]
    pub fn test_pckcerts_with_fallback() {
        let client = AzureProvisioningClientBuilder::new(PcsVersion::V3)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client());

        for pckid in PckID::parse_file(&PathBuf::from(PCKID_TEST_FILE).as_path())
            .unwrap()
            .iter()
        {
            let pckcerts = client.pckcerts_with_fallback(&pckid).unwrap();
            println!("Found {} PCK certs.", pckcerts.as_pck_certs().len());

            let tcb_info = client.tcbinfo(&pckcerts.fmspc().unwrap(), None).unwrap();
            let tcb_data = tcb_info.data().unwrap();

            let selected = pckcerts.select_pck(
                &tcb_data,
                &pckid.cpu_svn,
                pckid.pce_isvsvn,
                pckid.pce_id,
            ).unwrap();

            let pck = client.pckcert(
                Some(&pckid.enc_ppid),
                &pckid.pce_id,
                &pckid.cpu_svn,
                pckid.pce_isvsvn,
                Some(&pckid.qe_id),
            ).unwrap();

            assert_eq!(format!("{:?}", selected.sgx_extension().unwrap()), format!("{:?}", pck.sgx_extension().unwrap()));
        }
    }

    #[test]
    pub fn tcb_evaluation_data_numbers() {
        let client = AzureProvisioningClientBuilder::new(PcsVersion::V3)
            .set_retry_timeout(TIME_RETRY_TIMEOUT)
            .build(reqwest_client());
        assert!(client.tcb_evaluation_data_numbers().is_ok());
    }
}
