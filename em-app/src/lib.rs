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
use mbedtls::pk::Pk;
use pkix::{DerWrite, ToDer};
use pkix::bit_vec::BitVec;
use pkix::pem::{pem_to_der, der_to_pem, PEM_CERTIFICATE, PEM_CERTIFICATE_REQUEST};
use pkix::pkcs10::{CertificationRequest, CertificationRequestInfo};
use pkix::types::{Attribute, ObjectIdentifier, RsaPkcs15, Sha256, DerSequence};
use pkix;
use sgx_isa::{Report, Targetinfo};
use sgx_pkix::attestation::{SgxName,AttestationInlineSgxLocal, AttestationEmbeddedFqpe};
use sgx_pkix::oid;
use std::borrow::Cow;
use std::{error, fmt};

pub use mbedtls::rng::Rdrand as FtxRng;
type Result<T> = std::result::Result<T, Error>;
type RemoteError = Box<dyn error::Error>;

#[derive(Debug)]
pub enum Error {
    // Errors returned by ExternalKey trait functions.
    ExternalKey(RemoteError),

    // Errors establishing connection to node agent.
    NodeAgentClient(RemoteError),

    // Errors returned by remote calls when fetching target-info
    TargetReport(RemoteError),

    // Error creating a hash over target report.
    TargetReportHash(RemoteError),

    // Internal errors specific to parsing remote data or code issues when fetching target-info
    TargetReportInternal(String),

    // Errors when fetching attestation certificate.
    AttestationCert(RemoteError),

    // Errors when hashing data during attestation certificate processing.
    AttestationCertHash(RemoteError),

    // Internal errors specific to parsing remote data or code issues when fetching attestation certificates
    AttestationCertInternal(String),

    // Validation failed for data returned by Node Agent. (possibly tampered or protocol issues)
    AttestationCertValidation(String),

    // Error replies from Node Agent for certificate issue
    CertIssue(RemoteError),
}

impl fmt::Display for crate::Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            Error::ExternalKey(e)               => write!(f, "External key returned error: {}", e),
            Error::NodeAgentClient(e)           => write!(f, "Error creating node agent client: {}", e),
            Error::TargetReport(e)              => write!(f, "Unable to get target report from node agent: {}", e),
            Error::TargetReportHash(e)          => write!(f, "Failure in hash operations while processing target report: {}", e),
            Error::TargetReportInternal(e)      => write!(f, "Internal error in target report handling: {}", e),
            Error::AttestationCert(e)           => write!(f, "Failure requesting attestation certificate: {}", e),
            Error::AttestationCertHash(e)       => write!(f, "Failure in hash operations while processing attestation certificate: {}", e),
            Error::AttestationCertInternal(e)   => write!(f, "Internal error in processing attestation certificate: {}", e),
            Error::AttestationCertValidation(e) => write!(f, "Validation failed for data returned by Node Agent: {}", e),
            Error::CertIssue(e)                 => write!(f, "Failure in final certificate issue step: {}", e),
        }
    }
}

/// Operations needed on any input key pair. This is already implemented for mbedtls::Pk.
pub trait ExternalKey {
    fn get_public_key_der(&mut self) -> Result<Vec<u8>>;
    fn sign_sha256(&mut self, input: &[u8]) -> Result<Vec<u8>>;
}

/// Result of the certificate issuance operation.
pub struct FortanixEmCertificate {
    // Signed fortanix certificate with attestation extension.
    pub attestation_certificate_der: Option<Vec<u8>>,

    // Node agent certificate.
    pub node_certificate_der: Option<Vec<u8>>,

    // Response
    pub certificate_response: models::IssueCertificateResponse,
}

/// Issue fortanix EM Saas certificates
///
/// common_name - domain name to issue certificate for
/// key         - trait over public/private key pair that allows access to public key and to a sign operation.
/// 
pub fn get_fortanix_em_certificate(url: &str, common_name: &str, key: &mut dyn ExternalKey) -> Result<FortanixEmCertificate> {

    let mut client = Client::try_new_http(url).map_err(|e| Error::NodeAgentClient(Box::new(e)))?;

    // Get an SGX report for target info provided by remote
    let pub_key = key.get_public_key_der()?;
    let report = get_target_report(&mut client, &pub_key)?;

    // Create attestation CSR request
    let attestation = AttestationInlineSgxLocal { keyid: Cow::Borrowed(&report.keyid), mac: Cow::Borrowed(&report.mac) }.to_der();
    let csr = get_csr(common_name, &pub_key, &report, vec![(oid::attestationInlineSgxLocal.clone(), vec![attestation])]);
    let csr_pem = sign_csr(csr, key)?;

    // Send CSR to Node Agent and receive signed app/node/attestation certificates
    let (fqpe_cert, node_cert) = get_attestation_certificates(&mut client, &report, csr_pem)?;

    // Create main certificate CSR request
    let attestation = AttestationEmbeddedFqpe { app_cert: Cow::Borrowed(&fqpe_cert), node_cert: Cow::Borrowed(&node_cert) }.to_der();
    let attribute = vec![(oid::attestationEmbeddedFqpe.clone(), vec![attestation])];
    let csr = get_csr(common_name, &pub_key, &report, attribute);
    let csr_pem = sign_csr(csr, key)?;

    // Send the request
    let request = models::IssueCertificateRequest { csr: Some(csr_pem) };
    let result = client.issue_certificate(request).map_err(|e| Error::CertIssue(Box::new(e)))?;
    
    Ok(FortanixEmCertificate {
        attestation_certificate_der: Some(fqpe_cert),
        node_certificate_der: Some(node_cert),
        certificate_response: result,
    })
}

impl ExternalKey for Pk {
    fn get_public_key_der(&mut self) -> Result<Vec<u8>> {
        Ok(self.write_public_der_vec().map_err(|e| Error::ExternalKey(Box::new(e)))?)
    }
    
    fn sign_sha256(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut hash = [0u8; 32];
        hash::Md::hash(hash::Type::Sha256, &input, &mut hash).map_err(|e| Error::ExternalKey(Box::new(e)))?;
        
        let mut sig = vec![0u8; (self.len()+7)/8];
        self.sign(hash::Type::Sha256, &hash, &mut sig, &mut FtxRng).map_err(|e| Error::ExternalKey(Box::new(e)))?;
        Ok(sig)
    }
}

fn get_target_report(client: &mut Client, pub_key: &Vec<u8>) -> Result<sgx_isa::Report> {
    let result = client.get_target_info().map_err(|e| Error::TargetReport(Box::new(e)))?;
    
    let target_info = Targetinfo::try_copy_from(result.target_info.ok_or(Error::TargetReportInternal("Node Agent returned empty target_info".to_string()))?
                                                                  .from_base64().map_err(|e| Error::TargetReportInternal(format!("Base64 decode failed: {:?}", e)))?
                                                                  .as_ref()
                                               ).ok_or(Error::TargetReportInternal("Failed creating SGX structure from remote target info".to_string()))?;

    let mut data=[0u8;64];
    Md::hash(Type::Sha256, &pub_key, &mut data).map_err(|e| Error::TargetReportHash(Box::new(e)))?;
    Ok(sgx_isa::Report::for_target(&target_info, &data))        
}

fn get_csr(common_name: &str, pub_key_der: &[u8], report: &Report, attributes: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>) -> Vec<u8> {
    let mut sgx_name = SgxName::from_report(report, true);
    sgx_name.append(vec![(pkix::oid::commonName.clone(), common_name.to_string().into())]);

    let attributes = attributes.iter().map(|&(ref oid,ref elems)|
            Attribute {
                oid: oid.clone(),
                value: elems.iter().map(|e| e[..].into()).collect(),
            }
        ).collect::<Vec<_>>();
    
    pkix::yasna::construct_der(|writer| {
        CertificationRequestInfo {
            subject: sgx_name.to_name(),
            spki: DerSequence::from(&pub_key_der[..]),
            attributes: attributes,
        }.write(writer)
    })
}

fn sign_csr(reqinfo: Vec<u8>, key: &mut dyn ExternalKey) -> Result<String> {
    let sig = key.sign_sha256(&reqinfo)?;

    let csr = pkix::yasna::construct_der(|writer| {
        CertificationRequest {
            reqinfo: DerSequence::from(&reqinfo[..]),
            sigalg: RsaPkcs15(Sha256),
            sig: BitVec::from_bytes(&sig),
        }.write(writer)
    });

    Ok(der_to_pem(&csr, PEM_CERTIFICATE_REQUEST))
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
