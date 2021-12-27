#[cfg(test)]
#[macro_use] extern crate lazy_static;

use std::collections::BTreeMap;
use std::marker::PhantomData;
use serde::Deserialize;
use serde_bytes::ByteBuf;

#[cfg(feature = "crypto_mbedtls")]
use mbedtls8::{
    x509::{Certificate, VerifyError},
    alloc::{List as MbedtlsList}
};

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
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<u32, ByteBuf>,
    pub certificate: ByteBuf,
    pub cabundle: Vec<ByteBuf>,
    pub public_key: Option<ByteBuf>,
    pub user_data: Option<ByteBuf>,
    pub nonce: Option<ByteBuf>,
    #[serde(skip)]
    type_: PhantomData<V>,
}

impl<V: VerificationType> AttestationDocument<V> {
    fn verified(self) -> AttestationDocument<Verified> {
        // TODO: can be simplified once we have https://github.com/rust-lang/rust/issues/86555
        AttestationDocument {
            module_id: self.module_id,
            timestamp: self.timestamp,
            digest: self.digest,
            pcrs: self.pcrs,
            certificate: self.certificate,
            cabundle: self.cabundle,
            public_key: self.public_key,
            user_data: self.user_data,
            nonce: self.nonce,
            type_: Default::default(),
        }
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

pub fn get_unverified_document(token_data: &[u8]) -> Result<AttestationDocument<Unverified>, NitroError> {
    // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    let cose = aws_nitro_enclaves_cose::sign::CoseSign1::from_bytes(token_data).map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
    let payload = cose.get_payload(None).map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
    serde_cbor::from_slice(&payload).map_err(|e| NitroError::PayloadParsingFailure(format!("payload error: {}", e)))
}

pub fn get_verified_document(token_data: &[u8], root_certs_der: &[Vec<u8>], verify_type: VerifyType) -> Result<AttestationDocument<Verified>, NitroError> {
    // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    let cose = aws_nitro_enclaves_cose::sign::CoseSign1::from_bytes(token_data).map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
    let payload = cose.get_payload(None).map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
    let doc : AttestationDocument<Unverified> = serde_cbor::from_slice(&payload).map_err(|e| NitroError::PayloadParsingFailure(format!("payload error: {}", e)))?;
    verify_signature(&cose, doc, root_certs_der, verify_type)
}

#[cfg(feature = "crypto_mbedtls")]
fn verify_signature<V: VerificationType>(cose: &aws_nitro_enclaves_cose::sign::CoseSign1, doc: AttestationDocument<V>, root_certs_der: &[Vec<u8>], verify_type: VerifyType) -> Result<AttestationDocument<Verified>, NitroError> {
    let mut c_root = MbedtlsList::<Certificate>::new();

    
    for i in 0..root_certs_der.len() {
        let cert = Certificate::from_der(&root_certs_der[i]).map_err(|e| NitroError::CertificateParsingError(format!("Failed to parse root certificate[{}] as x509 certificate: {:?}", i, e)))?;
        c_root.push(cert);
    }

    let mut chain = MbedtlsList::<Certificate>::new();
    chain.push(Certificate::from_der(&doc.certificate).map_err(|e| NitroError::CertificateParsingError(format!("Certificate failure: {:?}", e)))?);
    
    for i in (0..doc.cabundle.len()).rev() {
        let cert = Certificate::from_der(&doc.cabundle[i]).map_err(|e| NitroError::CertificateParsingError(format!("Failed to parse doc.cabundle[{}] as x509 certificate: {:?}", i, e)))?;
        chain.push(cert);
    }


    let mut err_str = String::new();

    match verify_type {
        VerifyType::Full => Certificate::verify(&chain, &c_root, Some(&mut err_str)).map_err(|e| NitroError::CertificateVerifyFailure(format!("Certificate verify failure: {:?}, {}", e, err_str))),
        VerifyType::IgnoreExpiredCerts => {
            let verify_callback = |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
                verify_flags.remove(VerifyError::CERT_EXPIRED);
                Ok(())
            };
            Certificate::verify_callback(&chain, &c_root, Some(&mut err_str), verify_callback).map_err(|e| NitroError::CertificateVerifyFailure(format!("Certificate verify failure: {:?}, {}", e, err_str)))
        }
    }?;

    let certificate = chain.pop_front().ok_or(NitroError::CertificateInternalError)?;
    
    if !cose.verify_signature(certificate.public_key()).map_err(|err| NitroError::CertificateVerifyFailure(format!("failed to verify signature on sig_structure: {:?}", err)))? {
        Err(NitroError::FailedValidation)
    } else {
        Ok(doc.verified())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeZone, Utc};
    use crate::{get_verified_document, NitroError, VerifyType};
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
        let doc = get_verified_document(&PROPER_TOKEN, &AWS_CA, VerifyType::Full);
        let now = Utc::now();
        if now < PROPER_VALIDITY.0 {
            // Document not valid yet
            assert_eq!(doc.unwrap_err(), *NOT_VALID_YET_ERR);
            // faketime '2021-09-08 11:00:00 GMT'
        } else if PROPER_VALIDITY.1 < now {
            // Document expired
            assert_eq!(doc.unwrap_err(), *EXPIRED_ERR);
            // faketime '2021-09-10 11:00:00 GMT'
        } else {
            // Document valid
            let doc = doc.unwrap();
            assert_eq!(doc.module_id, "i-02e3a660059b27d87-enc017bca11991e5083");
            assert_eq!(doc.timestamp, 1631182760215);
            //faketime '2021-09-09 11:00:00 GMT'
        }
    }

    #[test]
    fn test_verify_multiple_root_cas() {
        let doc = get_verified_document(&PROPER_TOKEN, &BOTH_CAS, VerifyType::Full);
        let now = Utc::now();
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
        let res = get_verified_document(&PROPER_TOKEN, &INVALID_CA, VerifyType::Full);
        
        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }
    
    #[test]
    fn test_verify_attestation_invalid_leaf_certificate() {
        let res = get_verified_document(&TAMPERED_CERTIFICATE, &AWS_CA, VerifyType::Full);

        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_no_path_to_root_ca() {
        let _ = get_verified_document(&PROPER_TOKEN, &UNKNOWN_CA, VerifyType::Full).unwrap_err();
    }

    #[test]
    fn test_verify_attestation_not_signed_by_leaf_ca() {
        let doc = get_verified_document(&TAMPERED_SIGNATURE, &AWS_CA, VerifyType::Full);
        let now = Utc::now();
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

