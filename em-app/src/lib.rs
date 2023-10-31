/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#[macro_use]
pub extern crate serde_derive;

pub mod mbedtls_hyper;

pub mod utils;

use em_node_agent_client::{models, Api, Client};
use mbedtls::hash;
use pkix::types::Name;
use rustc_serialize::hex::FromHex;
use std::borrow::Cow;
use uuid::Uuid;

mod platform;

pub mod csr;
pub use csr::*;

pub mod error;
pub use error::*;
use yasna::models::TaggedDerValue;
use yasna::tags::TAG_UTF8STRING;
use sdkms::api_model::Blob;
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, Error>;

/// Result of the certificate issuance operation.
pub struct FortanixEmCertificate {
    // Signed fortanix certificate with attestation extension.
    pub attestation_certificate_der: Option<Vec<u8>>,

    // Node agent certificate.
    pub node_certificate_der: Option<Vec<u8>>,

    // Response
    pub certificate_response: models::IssueCertificateResponse,
}

pub fn common_name_to_subject(common_name: &str) -> Name {
    vec![(
        pkix::oid::commonName.clone(),
        TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, common_name.as_bytes().to_vec()),
    )]
    .into()
}

pub fn get_certificate_status(url: &str, task_id: Uuid) -> Result<models::IssueCertificateResponse> {
    let client = Client::try_new_http(url).map_err(|e| Error::NodeAgentClient(Box::new(e)))?;
    client.get_issue_certificate_response(task_id).map_err(|e| Error::NodeAgentClient(Box::new(e)))
}

pub fn get_fortanix_em_certificate_subject(
    url: &str,
    subject: &Name,
    signer: &mut dyn CsrSigner,
) -> Result<FortanixEmCertificate> {
    get_certificate_subject(url, subject, signer, None, None)
}

pub fn get_fortanix_em_certificate(
    url: &str,
    common_name: &str,
    signer: &mut dyn CsrSigner,
) -> Result<FortanixEmCertificate> {
    get_certificate(url, common_name, signer, None, None)
}


pub fn get_certificate_subject(
    url: &str,
    subject: &Name,
    signer: &mut dyn CsrSigner,
    alt_names: Option<Vec<Cow<str>>>,
    config_id: Option<&str>,
) -> Result<FortanixEmCertificate> {
    let pub_key = signer.get_public_key_der()?;
    let user_data = get_user_data(&pub_key, config_id)?;

    let (attestation_certificate_der, node_certificate_der, csr_pem) =
        platform::get_remote_attestation_parameters_subject(
            signer, url, subject, &user_data, alt_names,
        )?;

    let certificate_response = request_issue_certificate(url, csr_pem)?;

    Ok(FortanixEmCertificate {
        attestation_certificate_der,
        node_certificate_der,
        certificate_response,
    })
}

pub fn get_certificate(
    url: &str,
    common_name: &str,
    signer: &mut dyn CsrSigner,
    alt_names: Option<Vec<Cow<str>>>,
    config_id: Option<&str>,
) -> Result<FortanixEmCertificate> {
    let subject = common_name_to_subject(common_name);
    get_certificate_subject(url, &subject, signer, alt_names, config_id)
}

pub fn get_remote_attestation_csr_subject(
    url: &str,
    subject: &Name,
    signer: &mut dyn CsrSigner,
    alt_names: Option<Vec<Cow<str>>>,
    config_id: Option<&str>,
) -> Result<String> {
    let pub_key = signer.get_public_key_der()?;
    let user_data = get_user_data(&pub_key, config_id)?;
    let (_, _, csr_pem) = platform::get_remote_attestation_parameters_subject(
        signer, url, subject, &user_data, alt_names,
    )?;
    Ok(csr_pem)
}

pub fn get_remote_attestation_csr(
    url: &str,
    common_name: &str,
    signer: &mut dyn CsrSigner,
    alt_names: Option<Vec<Cow<str>>>,
    config_id: Option<&str>,
) -> Result<String> {
    let subject = common_name_to_subject(common_name);
    get_remote_attestation_csr_subject(url, &subject, signer, alt_names, config_id)
}

pub fn request_issue_certificate(url: &str, csr_pem: String) -> Result<models::IssueCertificateResponse> {
    let client = Client::try_new_http(url).map_err(|e| Error::NodeAgentClient(Box::new(e)))?;
    let request = models::IssueCertificateRequest { csr: Some(csr_pem) };
    client.issue_certificate(request).map_err(|e| Error::NodeAgentClient(Box::new(e)))
}

/// Computes application configuration hash
pub fn compute_app_config_hash(app_config: &BTreeMap<String, em_client::models::ApplicationConfigContents>,
                     labels: &BTreeMap<String, String>,
                     zone_ca: &BTreeSet<String>,
                     workflow: Option<&em_client::models::ApplicationConfigWorkflow>
) -> Result<Blob> {

    let hashed_config = HashedConfigRef {
        app_config,
        labels,
        zone_ca,
        workflow
    };

    let buffer = serde_json::to_string(&hashed_config).map_err(|e| Error::TargetReportHash(Box::new(e)))?;

    let mut digest = vec![0; 32];
    hash::Md::hash(hash::Type::Sha256, buffer.as_bytes(), &mut digest).map_err(|e| Error::TargetReportHash(Box::new(e)))?;

    Ok(Blob::from(digest.to_vec()))
}

#[derive(Debug, Serialize)]
struct HashedConfigRef<'a> {
    pub app_config: &'a BTreeMap<String, em_client::models::ApplicationConfigContents>,
    pub labels: &'a BTreeMap<String, String>,
    pub zone_ca: &'a BTreeSet<String>,

    #[serde(skip_serializing_if="Option::is_none")]
    pub workflow: Option<&'a em_client::models::ApplicationConfigWorkflow>,
}

fn get_user_data(pub_key: &Vec<u8>, config_id: Option<&str>) -> Result<[u8;64]> {
    let mut data=[0u8;64];
    hash::Md::hash(hash::Type::Sha256, &pub_key, &mut data).map_err(|e| Error::TargetReportHash(Box::new(e)))?;

    if let Some(id) = config_id {
        let id = id.from_hex().map_err(|e| Error::ConfigIdIssue(format!("Failed decoding config ID: {}", e)))?;
        if id.len() != 32 {
            return Err(Error::ConfigIdIssue(format!("config ID is invalid, length: {}, expected length: 32", id.len())));
        }

        let mut payload=[0u8;65];
        payload[0] = 1;
        payload[1..33].copy_from_slice(&data[0..32]);
        payload[33..65].copy_from_slice(&id[0..32]);

        // The payload is formed as follows in case of workflow report.

        // First 32 bytes is a Sha256 of (Version + public key sha256 + config-id)
        hash::Md::hash(hash::Type::Sha256, &payload, &mut data[0..32]).map_err(|e| Error::TargetReportHash(Box::new(e)))?;

        // Second 32 bytes part is the actual config-id.
        data[32..64].copy_from_slice(&id[0..32]);
    }
    // if non-workflow report then first 32 bytes is the hash of the public key, second 32 bytes are all 0.

    Ok(data)
}
