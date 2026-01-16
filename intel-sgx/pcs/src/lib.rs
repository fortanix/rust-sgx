/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#![deny(warnings)]

extern crate percent_encoding;
extern crate yasna;
#[macro_use]
extern crate quick_error;

use std::convert::TryFrom;
use std::fmt::{self, Display};

use serde::de::{self};
use serde::{Deserialize, Deserializer, Serialize};
pub use yasna::ASN1Error;
#[cfg(feature = "verify")]
use {
    mbedtls::Error as MbedError,
    mbedtls::alloc::{Box as MbedtlsBox, List as MbedtlsList},
    mbedtls::x509::certificate::Certificate,
    std::ffi::CString,
    std::ops::Deref,
};

pub use crate::pckcrl::PckCrl;
pub use crate::pckcrt::{PckCert, PckCerts, SGXPCKCertificateExtension, SGXType, TcbComponentType};
pub use crate::qe_identity::{EnclaveIdentity, QeIdentity, QeIdentitySigned};
pub use crate::tcb_info::{AdvisoryID, Fmspc, TcbInfo, TcbData, TcbLevel, TdxModule, TdxModuleIdentity, TdxModuleTcbLevel, TdxModuleTcbLevelIsvSvn, PlatformTypeForTcbInfo};
pub use crate::tcb_evaluation_data_numbers::{RawTcbEvaluationDataNumbers, TcbEvalNumber, TcbEvaluationDataNumbers, TcbPolicy};
pub use crate::io::{WriteOptions, WriteOptionsBuilder};

mod io;
mod iso8601;
mod pckcrl;
mod pckcrt;
mod pckid;
mod qe_identity;
mod tcb_info;
mod tcb_evaluation_data_numbers;

pub type CpuSvn = [u8; 16];
pub type EncPpid = Vec<u8>;
pub type PceId = u16;
pub type PceIsvsvn = u16;
pub type QeId = [u8; 16];
pub use crate::pckid::PckID;

pub trait PlatformType : Display + Clone {
    fn new() -> Self;
    fn platform_id() -> &'static str;
}

pub fn deserialize_platform_id<'de, D: Deserializer<'de>, T: PlatformTypeForTcbInfo<T>>(deserializer: D) -> Result<T, D::Error> {
    let platform_str = String::deserialize(deserializer)?;
    if platform_str == T::platform_id() {
        Ok(T::new())
    } else {
        Err(serde::de::Error::custom(format!("Invalid platform id: {platform_str}, expected {}", T::platform_id())))
    }            
}

pub mod platform {
    use std::fmt::{self, Display, Formatter};
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize, Clone, Default, Eq, PartialEq, Debug)]
    pub struct SGX;


    impl Display for SGX {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "Intel SGX")
        }
    }

    impl super::PlatformType for SGX {
        fn new() -> Self {
            Self {}
        }
        
        fn platform_id() -> &'static str {
            "SGX"
        }
    }

    #[derive(Serialize, Deserialize, Clone, Default, Eq, PartialEq, Debug)]
    pub struct TDX;

    impl Display for TDX {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
            write!(f, "Intel TDX")
        }
    }

    impl super::PlatformType for TDX {
        fn new() -> Self {
            Self {}
        }
        
        fn platform_id() -> &'static str {
            "TDX"
        }
    }
    
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        MissingCaChain{
            display("CA chain was unexpectedly empty")
        }
        IncorrectCA {
            display("Invalid CA")
        }
        InvalidCaFormat {
            display("CA certificate could not be parsed")
        }
        InvalidPckFormat(err: ASN1Error){
            display("Invalid formatted PckCert: {}", err)
        }
        InvalidPck(err: String){
            display("Invalid PCK: {}", err)
        }
        InvalidPcks(err: String){
            display("Invalid PCKs: {}", err)
        }
        InvalidFormatQe3Quote{
            display("Qe3 Quote could not be parsed")
        }
        NoPckForTcbFound{
            display("No PCK matching the TCB was found")
        }
        #[cfg(feature = "verify")]
        InvalidCrl(err: MbedError){
            display("Invalid CRL: {}", err)
        }
        InvalidCrlFormat{
            display("Invalid CRL format")
        }
        InvalidTcbInfo(err: String){
            display("Invalid TCB info: {}", err)
        }
        InvalidTcbEvaluationDataNumbers(err: String){
            display("Invalid TCB Evaluation Data Numbers: {}", err)
        }
        #[cfg(feature = "verify")]
        UntrustworthyTcbEvaluationDataNumber(err: MbedError) {
            display("TCB Evaluation Data Number not trustworthy: {}", err)
        }
        UnknownTcbType(tcb_type: u16){
            display("Unknown TCB type: {}", tcb_type)
        }
        #[cfg(feature = "verify")]
        InvalidQe3Id(err: MbedError){
            display("Invalid QE3 ID: {}", err)
        }
        Qe3NotValid(err: String){
            display("Invalid QE3: {}", err)
        }
        InvalidFormatQe3Identity{
            display("Invalid QE3 Identity format")
        }
        IoError(err: std::io::Error){
            display("I/O error: {}", err)
            from()
        }
        ParseError(err: serde_json::error::Error){
            from()
            display("json error: {}", err)
        }
        NoPckCertData{
            display("Empty PckCerts")
        }
        EncodingError(err: serde_json::error::Error){
            display("json error: {}", err)
        }
        UnknownTcbInfoVersion(version: u16){
            display("The TCB Info structure has unexpected version: {}", version)
        }
        UntrustedTcbInfoVersion(curr_version: u16, min_version: u16) {
            display("The TCB Info structure has version {curr_version}, while at least {min_version} is required")
        }
        EnclaveTcbLevelNotFound {
            display("TCB level not found for enclave")
        }
        UnknownQeIdentityVersion(version: u16){
            display("The QEIdentity structure has unexpected version: {}", version)
        }
        InvalidDcapAttestationFormat{
            display("The DCAP Attestation certificate has an unexpected format")
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum DcapArtifactIssuer {
    PCKPlatformCA,
    PCKProcessorCA,
    SGXRootCA,
}

impl TryFrom<&str> for DcapArtifactIssuer {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.contains("Intel SGX PCK Platform CA") {
            return Ok(DcapArtifactIssuer::PCKPlatformCA);
        }

        if value.contains("Intel SGX PCK Processor CA") {
            return Ok(DcapArtifactIssuer::PCKProcessorCA);
        }

        if value.contains("Intel SGX Root CA") {
            return Ok(DcapArtifactIssuer::SGXRootCA);
        }

        Err(Error::InvalidCaFormat)
    }
}

pub trait VerificationType {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified;

impl VerificationType for Verified {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unverified;

impl VerificationType for Unverified {}

/// Intel specifies raw ECDSA signatures in a different format than mbedtls. Convert ECDSA
/// signature to RFC5480 ASN.1 representation.
fn get_ecdsa_sig_der(sig: &[u8]) -> Result<Vec<u8>, ()> {
    if sig.len() % 2 != 0 {
        return Err(());
    }

    let (r_bytes, s_bytes) = sig.split_at(sig.len() / 2);
    let r = num::BigUint::from_bytes_be(r_bytes);
    let s = num::BigUint::from_bytes_be(s_bytes);

    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&r);
            writer.next().write_biguint(&s);
        })
    });

    Ok(der)
}

fn intel_signature_deserializer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let signature = String::deserialize(deserializer)?;
    let signature = &base16::decode(signature.as_bytes()).map_err(de::Error::custom)?;
    crate::get_ecdsa_sig_der(signature).map_err(|_| de::Error::custom("Failed ECDSA signature conversion"))
}

#[cfg(feature = "verify")]
fn create_cert_chain(certs: &Vec<String>) -> Result<(Vec<MbedtlsBox<Certificate>>, MbedtlsBox<Certificate>), Error> {
    fn str_to_cert_box(ca: &String) -> Result<MbedtlsBox<Certificate>, Error> {
        let ca = CString::new(ca.as_bytes()).map_err(|_| Error::InvalidCaFormat)?;
        Certificate::from_pem(ca.as_bytes_with_nul()).map_err(|_| Error::InvalidCaFormat)
    }
    if let Some((last_cert, certs)) = certs.split_last() {
        let chain = certs.iter().map(str_to_cert_box).collect::<Result<Vec<_>, _>>()?;
        let last_cert = str_to_cert_box(last_cert)?;
        Ok((chain, last_cert))
    } else {
        Err(Error::MissingCaChain)
    }
}

// Typically, certificates are verified directly against a pool of trusted root
// certificates. The DCAP attestation verification logic works differently.
// It first verifies against a root certificate included in the attestation,
// and then checks that the root certificate included in the attestation is
// a trusted root certificate.
//
// There are two different versions of the SGX root CA in circulation (both
// available in tests/data/ of this crate). They share the same key, but
// have a different expiration date and a different CRL reference (PEM vs. DER
// format). Because we have existing DCAP verifiers configured with only one
// of the certificates, we perform a certificate verification of the root
// in the attestation against the trusted root, rather than look for a
// byte-for-byte match between the attestation root and the trusted root.
#[cfg(feature = "verify")]
fn check_root_ca<B: Deref<Target = [u8]>>(trusted_root_certs: &[B], candidate: &MbedtlsList<Certificate>) -> Result<(), Error> {
    if trusted_root_certs
        .iter()
        .filter_map(|trusted_der| Certificate::from_der(&**trusted_der).ok())
        .any(|trusted| Certificate::verify(candidate, &std::iter::once(trusted).collect(), None, None).is_ok())
    {
        return Ok(());
    } else {
        return Err(Error::IncorrectCA);
    }
}

#[cfg(test)]
#[cfg(not(target_env = "sgx"))]
fn get_cert_subject(cert: &str) -> String {
    let der = &pkix::pem::pem_to_der(cert.trim(), Some(pkix::pem::PEM_CERTIFICATE))
        .ok_or(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
        .unwrap();
    get_cert_subject_from_der(der)
}

#[cfg(test)]
#[cfg(not(target_env = "sgx"))]
fn get_cert_subject_from_der(cert: &Vec<u8>) -> String {
    use pkix::FromBer;
    let cert = pkix::x509::GenericCertificate::from_ber(&cert).unwrap();
    let name = cert.tbscert.subject.get(&*pkix::oid::commonName).unwrap();
    String::from_utf8_lossy(&name.value()).to_string()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Copy)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl TcbStatus {
    pub(crate) fn drop_sw_hardening_needed(self) -> Self {
        match self {
            Self::SWHardeningNeeded => Self::UpToDate,
            Self::ConfigurationAndSWHardeningNeeded => Self::ConfigurationNeeded,
            v => v,
        }
    }
}

impl fmt::Display for TcbStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcbStatus::UpToDate => write!(f, "Up to Date"),
            TcbStatus::SWHardeningNeeded => write!(f, "Software Hardening Needed"),
            TcbStatus::ConfigurationNeeded => write!(f, "Configuration Needed"),
            TcbStatus::ConfigurationAndSWHardeningNeeded => write!(f, "Configuration And Software Hardening Needed"),
            TcbStatus::OutOfDate => write!(f, "Out of Date"),
            TcbStatus::OutOfDateConfigurationNeeded => write!(f, "Out of Date, Configuration Needed"),
            TcbStatus::Revoked => write!(f, "Revoked"),
        }
    }
}
