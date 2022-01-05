#![deny(warnings)]
#[cfg(test)]
#[macro_use] extern crate lazy_static;

use aws_nitro_enclaves_cose::CoseSign1;
use mbedtls8::pk::Pk as MbedtlsPk;
use mbedtls8::alloc::Box as MbedtlsBox;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use mbedtls8::{
    x509::Certificate,
    alloc::{List as MbedtlsList}
};

mod mbedtls;
use crate::mbedtls::Mbedtls;

pub trait VerificationType {}

#[derive(Clone, Debug)]
pub struct Verified;
impl VerificationType for Verified{}

#[derive(Clone, Debug)]
pub struct Unverified;
impl VerificationType for Unverified{}

pub trait SafeToDeserialize {}
impl SafeToDeserialize for Unverified{}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "V: SafeToDeserialize"))]
pub struct AttestationDocument<V: VerificationType = Verified> {
    module_id: String,
    timestamp: u64,
    digest: String,
    pcrs: BTreeMap<u32, ByteBuf>,
    certificate: ByteBuf,
    cabundle: Vec<ByteBuf>,
    public_key: Option<ByteBuf>,
    user_data: Option<ByteBuf>,
    nonce: Option<ByteBuf>,
    #[serde(skip)]
    cose: Option<CoseSign1>,
    #[serde(skip)]
    type_: PhantomData<V>,
}

impl<V: VerificationType> AttestationDocument<V> {
    pub fn module_id(&self) -> &String {
        &self.module_id
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn digest(&self) -> &String {
        &self.digest
    }

    pub fn pcrs(&self) -> &BTreeMap<u32, ByteBuf> {
        &self.pcrs
    }

    pub fn certificate(&self) -> &ByteBuf {
        &self.certificate
    }

    pub fn cabundle(&self) -> &Vec<ByteBuf> {
        &self.cabundle
    }

    pub fn public_key(&self) -> Option<&ByteBuf> {
        self.public_key.as_ref()
    }

    pub fn user_data(&self) -> Option<&ByteBuf> {
        self.user_data.as_ref()
    }

    pub fn nonce(&self) -> Option<&ByteBuf> {
        self.nonce.as_ref()
    }
}

impl AttestationDocument<Unverified> {
    pub fn from_slice(data: &[u8]) -> Result<Self, NitroError> {
        // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        let cose = CoseSign1::from_bytes(data)
                    .map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
        let payload = cose.get_payload::<Mbedtls>(None)
                        .map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
        let mut doc: AttestationDocument<Unverified> = serde_cbor::from_slice(&payload)
                                                        .map_err(|e| NitroError::PayloadParsingFailure(format!("payload error: {}", e)))?;
        doc.cose = Some(cose);
        Ok(doc)
    }

    /// Verifies the `AttestationDocument` given `root_certs` as DER-encoded trusted root CAs
    pub fn verify(self, root_certs: &[Vec<u8>]) -> Result<AttestationDocument, NitroError> {
        self.verify_ex(root_certs, verify_certificates)
    }

    /// Expert version of the `verify` function. Verifies the `AttestationDocument` given `root_certs` as
    /// DER-encoded trusted root CAs and a `verify_certs` function that takes the signing
    /// certificate, CA bundle and root certificates as input.
    pub fn verify_ex<F>(self, root_certs_der: &[Vec<u8>], verify_certs: F) -> Result<AttestationDocument, NitroError>
        where
        F: FnOnce(&ByteBuf, &Vec<ByteBuf>, &[Vec<u8>]) -> Result<MbedtlsBox<Certificate>, NitroError>
    {
        // By construction an AttestationDocument<Unverified> always has a `cose` field
        let signing_cert = verify_certs(
                         &self.certificate,
                         &self.cabundle,
                         root_certs_der)?;
        let cose = self.cose.as_ref().ok_or(NitroError::MissingValue("COSE value not present"))?;
        verify_signature(cose, signing_cert.public_key())?;
        // TODO: can be simplified once we have https://github.com/rust-lang/rust/issues/86555
        Ok(AttestationDocument {
            module_id: self.module_id,
            timestamp: self.timestamp,
            digest: self.digest,
            pcrs: self.pcrs,
            certificate: self.certificate,
            cabundle: self.cabundle,
            public_key: self.public_key,
            user_data: self.user_data,
            nonce: self.nonce,
            cose: self.cose,
            type_: PhantomData,
            })
    }
}

#[derive(Debug, PartialEq)]
pub enum NitroError {
    CoseParsingFailure(String),
    PayloadParsingFailure(String),
    InvalidValue(&'static str),
    MissingValue(&'static str),
    FailedValidation,
    FailedValidationDetails(String),
    CertificateParsingError(String),
    CertificateVerifyFailure(String),
    CertificateInternalError,
    CertificateInternalErrorDetails(String),
}

impl std::fmt::Display for NitroError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NitroError::CoseParsingFailure(ref msg) => write!(fmt, "CoseParsingFailure: {}", msg),
            NitroError::PayloadParsingFailure(ref msg) => write!(fmt, "PayloadParsingFailure: {}", msg),
            NitroError::InvalidValue(ref msg) => write!(fmt, "InvalidValue {}", msg),
            NitroError::MissingValue(ref msg) => write!(fmt, "MissingValue {}", msg),
            NitroError::FailedValidation => write!(fmt, "FailedValidation"),
            NitroError::FailedValidationDetails(ref msg) => write!(fmt, "FailedValidation {}", msg),
            NitroError::CertificateParsingError(ref msg) => write!(fmt, "CertificateParsingError: {}", msg),
            NitroError::CertificateVerifyFailure(ref msg) => write!(fmt, "CertificateVerifyFailure: {}", msg),
            NitroError::CertificateInternalError => write!(fmt, "CertificateInternalError"),
            NitroError::CertificateInternalErrorDetails(ref msg) => write!(fmt, "CertificateInternalError: {}", msg),
        }
    }
}

impl std::error::Error for NitroError {
    fn description(&self) -> &str {
        match self {
            NitroError::CoseParsingFailure(_) => "CoseParsingFailure",
            NitroError::PayloadParsingFailure(_) => "PayloadParsingFailure",
            NitroError::InvalidValue(_) => "InvalidValue",
            NitroError::MissingValue(_) => "MissingValue",
            NitroError::FailedValidation => "FailedValidation",
            NitroError::FailedValidationDetails(_) => "FailedValidation",
            NitroError::CertificateParsingError(_) => "CertificateParsingError",
            NitroError::CertificateVerifyFailure(_) => "CertificateVerifyFailure",
            NitroError::CertificateInternalError => "CertificateInternalError",
            NitroError::CertificateInternalErrorDetails(_) => "CertificateInternalError",
        }
    }
}

fn verify_certificates(certificate: &ByteBuf, cabundle: &Vec<ByteBuf>, root_certs_der: &[Vec<u8>]) -> Result<MbedtlsBox<Certificate>, NitroError> {
    let mut c_root = MbedtlsList::<Certificate>::new();

    for i in 0..root_certs_der.len() {
        let cert = Certificate::from_der(&root_certs_der[i]).map_err(|e| NitroError::CertificateParsingError(format!("Failed to parse root certificate[{}] as x509 certificate: {:?}", i, e)))?;
        c_root.push(cert);
    }

    let mut chain = MbedtlsList::<Certificate>::new();
    chain.push(Certificate::from_der(certificate).map_err(|e| NitroError::CertificateParsingError(format!("Certificate failure: {:?}", e)))?);
    
    for i in (0..cabundle.len()).rev() {
        let cert = Certificate::from_der(&cabundle[i]).map_err(|e| NitroError::CertificateParsingError(format!("Failed to parse doc.cabundle[{}] as x509 certificate: {:?}", i, e)))?;
        chain.push(cert);
    }


    let mut err_str = String::new();
    Certificate::verify(&chain, &c_root, Some(&mut err_str))
        .map_err(|e| NitroError::CertificateVerifyFailure(format!("Certificate verify failure: {:?}, {}", e, err_str)))?;


    let certificate = chain.pop_front().ok_or(NitroError::CertificateInternalError)?;
    Ok(certificate)
}

fn verify_signature(cose: &CoseSign1, key: &MbedtlsPk) -> Result<(), NitroError> {
    let key = mbedtls::Pk::from(key);
    if !cose.verify_signature::<Mbedtls>(&key).map_err(|err| NitroError::CertificateVerifyFailure(format!("failed to verify signature on sig_structure: {:?}", err)))? {
        Err(NitroError::FailedValidation)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use crate::{AttestationDocument, NitroError};
    use pkix::pem::{pem_to_der, PEM_CERTIFICATE};

    lazy_static!{
        static ref UNKNOWN_CA: Vec<Vec<u8>> = vec![pem_to_der(include_str!("../data/unknown_ca.crt"), Some(PEM_CERTIFICATE)).unwrap()];
        static ref AWS_CA: Vec<Vec<u8>> = vec![pem_to_der(include_str!("../data/aws.crt"), Some(PEM_CERTIFICATE)).unwrap()];

        static ref BOTH_CAS: Vec<Vec<u8>> = vec![pem_to_der(include_str!("../data/unknown_ca.crt"), Some(PEM_CERTIFICATE)).unwrap(),
                                                 pem_to_der(include_str!("../data/aws.crt"), Some(PEM_CERTIFICATE)).unwrap()];
        
        static ref INVALID_CA: Vec<Vec<u8>> = vec![pem_to_der(include_str!("../data/tampered_root_cert.crt"), Some(PEM_CERTIFICATE)).unwrap()];

        // Serial Number:
        //   01:7b:ca:11:99:1e:50:83:00:00:00:00:61:39:df:a8
        // Validity
        //   Not Before: Sep  9 10:19:20 2021 GMT
        //   Not After : Sep  9 13:19:20 2021 GMT
        static ref PROPER_TOKEN : Vec<u8> = include_bytes!("../data/request_proper.bin").to_vec();
        static ref PROPER_VALIDITY: (DateTime<Utc>, DateTime<Utc>) = (Utc.ymd(2021, 9, 9).and_hms(10, 19, 19),  Utc.ymd(2021, 9, 9).and_hms(13, 19, 21));
        static ref NOT_VALID_YET_ERR: NitroError = NitroError::CertificateVerifyFailure("Certificate verify failure: X509CertVerifyFailed, The certificate validity starts in the future\n".to_string());
        static ref EXPIRED_ERR: NitroError = NitroError::CertificateVerifyFailure("Certificate verify failure: X509CertVerifyFailed, The certificate validity has expired\n".to_string());
        static ref TAMPERED_SIGNATURE : Vec<u8> = include_bytes!("../data/tampered_signature.bin").to_vec();
        static ref TAMPERED_CERTIFICATE : Vec<u8> = include_bytes!("../data/tampered_certificate.bin").to_vec();
    }
    
    #[test]
    fn test_verify_proper() {
        let doc = AttestationDocument::from_slice(&PROPER_TOKEN).unwrap().verify(&AWS_CA);
        let now = Utc::now();
        println!("now = {}", now);
        if now < PROPER_VALIDITY.0 {
            // Document not valid yet
            assert_eq!(doc.unwrap_err(), *NOT_VALID_YET_ERR);
        } else if PROPER_VALIDITY.1 < now {
            // Document expired
            assert_eq!(doc.unwrap_err(), *EXPIRED_ERR);
        } else {
            // Document valid
            let doc = doc.unwrap();
            assert_eq!(doc.module_id, "i-02e3a660059b27d87-enc017bca11991e5083");
            assert_eq!(doc.timestamp, 1631182760215);
        }
    }

    #[test]
    fn test_verify_multiple_root_cas() {
        let doc = AttestationDocument::from_slice(&PROPER_TOKEN).unwrap().verify(&BOTH_CAS);
        let now = Utc::now();
        println!("now = {}", now);
        if now < PROPER_VALIDITY.0 {
            // Document not valid yet
            assert_eq!(doc.unwrap_err(), *NOT_VALID_YET_ERR);
        } else if PROPER_VALIDITY.1 < now {
            // Document expired
            assert_eq!(doc.unwrap_err(), *EXPIRED_ERR);
        } else {
            // Document valid
            let doc = doc.unwrap();
            assert_eq!(doc.module_id, "i-02e3a660059b27d87-enc017bca11991e5083");
            assert_eq!(doc.timestamp, 1631182760215);
        }
    }

    #[test]
    fn test_verify_invalid_root_cas() {
        let res = AttestationDocument::from_slice(&PROPER_TOKEN).unwrap().verify(&INVALID_CA);
        
        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }
    
    #[test]
    fn test_verify_attestation_invalid_leaf_certificate() {
        let res = AttestationDocument::from_slice(&TAMPERED_CERTIFICATE).unwrap().verify(&AWS_CA);

        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_no_path_to_root_ca() {
        let _ = AttestationDocument::from_slice(&PROPER_TOKEN).unwrap().verify(&UNKNOWN_CA).unwrap_err();
    }

    #[test]
    fn test_verify_attestation_not_signed_by_leaf_ca() {
        let doc = AttestationDocument::from_slice(&TAMPERED_SIGNATURE).unwrap().verify(&AWS_CA);
        let now = Utc::now();
        println!("now = {}", now);
        if now < PROPER_VALIDITY.0 {
            // Document not valid yet
            assert_eq!(doc.unwrap_err(), *NOT_VALID_YET_ERR);
        } else if PROPER_VALIDITY.1 < now {
            // Document expired
            assert_eq!(doc.unwrap_err(), *EXPIRED_ERR);
        } else {
            assert_eq!(doc.unwrap_err(), NitroError::FailedValidation);
        }
    }
}

