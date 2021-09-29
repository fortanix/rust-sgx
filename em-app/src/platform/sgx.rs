/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use b64_ct::{ToBase64, FromBase64, STANDARD};
use em_node_agent_client::{Api, Client, models};
use mbedtls::cipher::{Cipher, raw};
use mbedtls::hash::{Type,Md};
use mbedtls::hash;
use pkix::{DerWrite, ToDer};
use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
use pkix;
use sgx_isa::{Report, Targetinfo};
use sgx_pkix::attestation::{AttestationInlineSgxLocal, AttestationEmbeddedFqpe};
use sgx_pkix::oid;
use std::borrow::Cow;
use pkix::x509::DnsAltNames;
use sgx_pkix::attestation::{SgxName};

use crate::{CsrSigner, Error, get_csr};

type Result<T> = std::result::Result<T, Error>;

pub fn get_remote_attestation_parameters(
    signer: &mut dyn CsrSigner,
    url: &str, 
    common_name: &str, 
    user_data: &[u8;64],
    alt_names: Option<Vec<Cow<str>>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, String)> {

    let mut client = Client::try_new_http(url).map_err(|e| Error::NodeAgentClient(Box::new(e)))?;

    // Get an SGX report for target info provided by remote
    let report = get_target_report(&mut client, user_data)?;

    // Create attestation CSR request
    let attestation = AttestationInlineSgxLocal {
        keyid: Cow::Borrowed(&report.keyid),
        mac: Cow::Borrowed(&report.mac)
    }.to_der().into();

    let attributes = vec![(oid::attestationInlineSgxLocal.clone(), vec![attestation])];
    let extensions = alt_names.and_then(|names| {
        Some(vec![(pkix::oid::subjectAltName.clone(), false, pkix::yasna::construct_der(|w| DnsAltNames { names }.write(w)).into())])
    });

    let mut sgx_name = SgxName::from_report(&report, true);
    sgx_name.append(vec![(pkix::oid::commonName.clone(), common_name.to_string().into())]);
    let subject = sgx_name.to_name();
    
    let csr_pem = get_csr(signer, &subject, attributes, &extensions)?;

    // Send CSR to Node Agent and receive signed app/node/attestation certificates
    let (fqpe_cert, node_cert) = get_attestation_certificates(&mut client, &report, csr_pem)?;

    // Create main certificate CSR request
    let attestation = AttestationEmbeddedFqpe {
        app_cert: Cow::Borrowed(&fqpe_cert),
        node_cert: Cow::Borrowed(&node_cert)
    }.to_der().into();
    let attributes = vec![(oid::attestationEmbeddedFqpe.clone(), vec![attestation])];

    let csr_pem = get_csr(signer, &subject, attributes, &extensions)?;

    Ok((Some(fqpe_cert), Some(node_cert), csr_pem))
}

fn get_target_report(client: &mut Client, user_data: &[u8;64]) -> Result<sgx_isa::Report> {
    let result = client.get_target_info().map_err(|e| Error::TargetReport(Box::new(e)))?;
    
    let target_info = Targetinfo::try_copy_from(
        result.target_info.ok_or(Error::TargetReportInternal("Node Agent returned empty target_info".to_string()))?
            .from_base64().map_err(|e| Error::TargetReportInternal(format!("Base64 decode failed: {:?}", e)))?
            .as_ref()
    ).ok_or(Error::TargetReportInternal("Failed creating SGX structure from remote target info".to_string()))?;
    
    Ok(sgx_isa::Report::for_target(&target_info, user_data))
}


fn get_attestation_certificates(client: &mut Client, report: &Report, csr_pem: String) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut corr_report_bytes = vec![0; Report::UNPADDED_SIZE];
    corr_report_bytes.copy_from_slice(report.as_ref());
    
    let request = models::GetFortanixAttestationRequest {
        report: Some(corr_report_bytes.to_base64(STANDARD)),
        attestation_csr: Some(csr_pem),
    };
    
    let result = client.get_fortanix_attestation(request).map_err(|e| Error::AttestationCert(Box::new(e)))?;
    
    let qe_report = Report::try_copy_from(result.fqpe_report.ok_or(Error::AttestationCertInternal("No fqpe report returned by node agent".to_string()))?
                                                            .from_base64().map_err(|e| Error::AttestationCertInternal(format!("Base64 decode failed: {:?}", e)))?
                                                            .as_ref()
                                         ).ok_or(Error::AttestationCertInternal("Failed parsing fpqe report".to_string()))?;

    let cipher = Cipher::new(raw::CipherId::Aes, raw::CipherMode::ECB, 128).map_err(|e| Error::AttestationCertHash(Box::new(e)))?;
    if !qe_report.verify(|key, in_data, out_data| {
        let mut out = [0; 16];
        if let Ok(_) = cipher.cmac(key, in_data, &mut out) {
            compare_ct(&*out_data, &out)
        } else {
            false
        }
    }) {
        return Err(Error::AttestationCertValidation("Failed validating SGX report".to_string()));
    }

    let fqpe_cert = pem_to_der(&result.attestation_certificate.ok_or(Error::AttestationCertInternal("No attestation certificate returned by node agent".to_string()))?,
                               Some(PEM_CERTIFICATE)).ok_or(Error::AttestationCertInternal("Failed decoding attestation certificate pem".to_string()))?;

    let mut data=[0u8;64];
    Md::hash(Type::Sha256, &fqpe_cert, &mut data).map_err(|e| Error::AttestationCertHash(Box::new(e)))?;

    if !compare_ct(&qe_report.reportdata, &data) {
        return Err(Error::AttestationCertValidation("attestation certificate hash does not match SGX report data".to_string()));
    }

    let node_cert = pem_to_der(&result.node_certificate.ok_or(Error::AttestationCertInternal("No node certificate returned by node agent".to_string()))?,
                               Some(PEM_CERTIFICATE)).ok_or(Error::AttestationCertInternal("Failed decoding node cert pem".to_string()))?;

    Ok((fqpe_cert, node_cert))
}

fn compare_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut ah = [0u8; 32];
    let mut bh = [0u8; 32];
    hash::Md::hash(hash::Type::Sha256, a, &mut ah).unwrap();
    hash::Md::hash(hash::Type::Sha256, b, &mut bh).unwrap();
    ah == bh
}
