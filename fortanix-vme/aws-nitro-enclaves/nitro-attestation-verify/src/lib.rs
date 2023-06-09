/* Copyright (c) Fortanix, Inc.                                                                                                                                                                                                          
 *                                                                                                                                                                                                                                       
 * This Source Code Form is subject to the terms of the Mozilla Public                                                                                                                                                                   
 * License, v. 2.0. If a copy of the MPL was not distributed with this                                                                                                                                                                   
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#![deny(warnings)]
#[cfg(all(test, feature = "mbedtls"))]
#[macro_use]
extern crate lazy_static;

pub use aws_nitro_enclaves_cose::crypto::{Hash, SigningPublicKey};
use aws_nitro_enclaves_cose::CoseSign1;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::marker::PhantomData;

#[cfg(feature = "mbedtls")]
use ::mbedtls::{alloc::List as MbedtlsList, x509::{Certificate, VerifyError}};

#[cfg(feature = "mbedtls")]
mod mbedtls;

#[cfg(feature = "mbedtls")]
pub use crate::mbedtls::Mbedtls;

pub trait VerificationType {}

#[derive(Clone, Debug)]
pub struct Verified;
impl VerificationType for Verified {}

#[derive(Clone, Debug)]
pub struct Unverified;
impl VerificationType for Unverified {}

#[derive(Clone, Debug)]
pub struct Expired;
impl VerificationType for Expired {}

pub trait SafeToDeserialize {}
impl SafeToDeserialize for Unverified {}

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

    /// Returns whether the enclave is executing in debug mode.
    pub fn debug(&self) -> bool {
        self.pcrs.range(0..=2).any(|(_idx, pcr)| pcr.iter().all(|v| *v == 0))
    }
}

impl AttestationDocument<Unverified> {
    pub fn from_slice<H: Hash>(data: &[u8]) -> Result<Self, NitroError> {
        // https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        let cose = CoseSign1::from_bytes(data)
            .map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
        let payload = cose
            .get_payload::<H>(None)
            .map_err(|err| NitroError::CoseParsingFailure(format!("cose error: {:?}", err)))?;
        let mut doc: AttestationDocument<Unverified> = serde_cbor::from_slice(&payload)
            .map_err(|e| NitroError::PayloadParsingFailure(format!("payload error: {}", e)))?;
        doc.cose = Some(cose);
        Ok(doc)
    }

    /// Verifies the `AttestationDocument` given `root_certs` as DER-encoded trusted root CAs
    /// This only indicates that the `AttestationDocument` was ultimately signed by a root cert. It
    /// doesn't say anything about the trustworthyness of the `AttestationDocument`. Users should:
    ///  - Verify that the `AttestationDocument` is not a debug document
    ///  - Verify the contents of the enclosed PCRs
    #[cfg(feature = "mbedtls")]
    pub fn verify(self, root_certs: &[Vec<u8>]) -> Result<AttestationDocument, NitroError> {
        self.verify_ex::<_, Mbedtls, _>(root_certs, verify_certificates, false)?;
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

    #[cfg(feature = "mbedtls")]
    pub fn verify_expired(self, root_certs: &[Vec<u8>]) -> Result<AttestationDocument<Expired>, NitroError> {
        self.verify_ex::<_, Mbedtls, _>(root_certs, verify_certificates, true)?;
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

    /// Expert version of the `verify` function. Verifies the `AttestationDocument` given `root_certs` as
    /// DER-encoded trusted root CAs and a `verify_certs` function that takes as input the signing
    /// certificate, CA bundle, root certificates, and whether certificate expiration dates should be ignored
    pub fn verify_ex<K, H, F>(
        &self,
        root_certs_der: &[Vec<u8>],
        verify_certs: F,
        ignore_expiration: bool,
    ) -> Result<(), NitroError>
    where
        K: SigningPublicKey,
        H: Hash,
        F: FnOnce(&ByteBuf, &Vec<ByteBuf>, &[Vec<u8>], bool) -> Result<K, NitroError>,
    {
        let signing_cert = verify_certs(&self.certificate, &self.cabundle, root_certs_der, ignore_expiration)?;
        // By construction an AttestationDocument<Unverified> always has a `cose` field
        let cose = self
            .cose
            .as_ref()
            .ok_or(NitroError::MissingValue("COSE value not present"))?;
        verify_signature::<H>(cose, &signing_cert)?;
        Ok(())
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
            NitroError::PayloadParsingFailure(ref msg) => {
                write!(fmt, "PayloadParsingFailure: {}", msg)
            }
            NitroError::InvalidValue(ref msg) => write!(fmt, "InvalidValue {}", msg),
            NitroError::MissingValue(ref msg) => write!(fmt, "MissingValue {}", msg),
            NitroError::FailedValidation => write!(fmt, "FailedValidation"),
            NitroError::FailedValidationDetails(ref msg) => write!(fmt, "FailedValidation {}", msg),
            NitroError::CertificateParsingError(ref msg) => {
                write!(fmt, "CertificateParsingError: {}", msg)
            }
            NitroError::CertificateVerifyFailure(ref msg) => {
                write!(fmt, "CertificateVerifyFailure: {}", msg)
            }
            NitroError::CertificateInternalError => write!(fmt, "CertificateInternalError"),
            NitroError::CertificateInternalErrorDetails(ref msg) => {
                write!(fmt, "CertificateInternalError: {}", msg)
            }
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

#[cfg(feature = "mbedtls")]
fn verify_certificates(
    certificate: &ByteBuf,
    cabundle: &Vec<ByteBuf>,
    root_certs_der: &[Vec<u8>],
    ignore_expiration: bool,
) -> Result<mbedtls::WrappedCert, NitroError> {
    let mut c_root = MbedtlsList::<Certificate>::new();

    for i in 0..root_certs_der.len() {
        let cert = Certificate::from_der(&root_certs_der[i]).map_err(|e| {
            NitroError::CertificateParsingError(format!(
                "Failed to parse root certificate[{}] as x509 certificate: {:?}",
                i, e
            ))
        })?;
        c_root.push(cert);
    }

    let mut chain = MbedtlsList::<Certificate>::new();
    chain.push(Certificate::from_der(certificate).map_err(|e| {
        NitroError::CertificateParsingError(format!("Certificate failure: {:?}", e))
    })?);

    for i in (0..cabundle.len()).rev() {
        let cert = Certificate::from_der(&cabundle[i]).map_err(|e| {
            NitroError::CertificateParsingError(format!(
                "Failed to parse doc.cabundle[{}] as x509 certificate: {:?}",
                i, e
            ))
        })?;
        chain.push(cert);
    }

    let verify_callback = move |_crt: &Certificate, _depth: i32, verify_flags: &mut VerifyError| {
        if ignore_expiration {
            verify_flags.remove(VerifyError::CERT_EXPIRED);
        }
        Ok(())
    };
    let mut err_str = String::new();
    Certificate::verify_with_callback(&chain, &c_root, None, Some(&mut err_str), verify_callback)
        .map_err(|e| NitroError::CertificateVerifyFailure(format!("Certificate verify failure: {:?}, {}", e, err_str)))?;

    let certificate = chain
        .pop_front()
        .ok_or(NitroError::CertificateInternalError)?;
    Ok(mbedtls::WrappedCert::new(certificate))
}

fn verify_signature<H: Hash>(
    cose: &CoseSign1,
    key: &dyn SigningPublicKey,
) -> Result<(), NitroError> {
    if !cose.verify_signature::<H>(key).map_err(|err| {
        NitroError::CertificateVerifyFailure(format!(
            "failed to verify signature on sig_structure: {:?}",
            err
        ))
    })? {
        Err(NitroError::FailedValidation)
    } else {
        Ok(())
    }
}

#[cfg(all(test, feature = "mbedtls"))]
mod tests {
    use crate::{AttestationDocument, Mbedtls, NitroError};
    use chrono::{DateTime, TimeZone, Utc};
    use pkix::pem::{pem_to_der, PEM_CERTIFICATE};

    lazy_static! {
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
        static ref NOT_VALID_YET_ERR: NitroError = NitroError::CertificateVerifyFailure("Certificate verify failure: HighLevel(X509CertVerifyFailed), The certificate validity starts in the future\n".to_string());
        static ref EXPIRED_ERR: NitroError = NitroError::CertificateVerifyFailure("Certificate verify failure: HighLevel(X509CertVerifyFailed), The certificate validity has expired\n".to_string());
        static ref TAMPERED_SIGNATURE : Vec<u8> = include_bytes!("../data/tampered_signature.bin").to_vec();
        static ref TAMPERED_CERTIFICATE : Vec<u8> = include_bytes!("../data/tampered_certificate.bin").to_vec();
    }

    #[test]
    fn test_verify_proper() {
        let doc = AttestationDocument::from_slice::<Mbedtls>(&PROPER_TOKEN)
            .unwrap()
            .verify(&AWS_CA);
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
    fn test_verify_expired() {
        let doc = AttestationDocument::from_slice::<Mbedtls>(&PROPER_TOKEN)
            .unwrap()
            .verify_expired(&AWS_CA);
        // Document valid
        let doc = doc.unwrap();
        assert_eq!(doc.module_id, "i-02e3a660059b27d87-enc017bca11991e5083");
        assert_eq!(doc.timestamp, 1631182760215);
        println!("pcrs: {:?}", doc.pcrs());
        assert!(doc.debug());
    }

    #[test]
    fn test_verify_multiple_root_cas() {
        let doc = AttestationDocument::from_slice::<Mbedtls>(&PROPER_TOKEN)
            .unwrap()
            .verify(&BOTH_CAS);
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
        let res = AttestationDocument::from_slice::<Mbedtls>(&PROPER_TOKEN)
            .unwrap()
            .verify(&INVALID_CA);

        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_attestation_invalid_leaf_certificate() {
        let res = AttestationDocument::from_slice::<Mbedtls>(&TAMPERED_CERTIFICATE)
            .unwrap()
            .verify(&AWS_CA);

        match res.unwrap_err() {
            NitroError::CertificateParsingError(_) => (),
            e => assert!(false, "Invalid error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_no_path_to_root_ca() {
        let _ = AttestationDocument::from_slice::<Mbedtls>(&PROPER_TOKEN)
            .unwrap()
            .verify(&UNKNOWN_CA)
            .unwrap_err();
    }

    #[test]
    fn test_verify_attestation_not_signed_by_leaf_ca() {
        let doc = AttestationDocument::from_slice::<Mbedtls>(&TAMPERED_SIGNATURE)
            .unwrap()
            .verify(&AWS_CA);
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
