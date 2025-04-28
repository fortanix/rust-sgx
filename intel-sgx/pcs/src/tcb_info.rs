/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::convert::TryFrom;
use std::marker::PhantomData;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::List as MbedtlsList, mbedtls::x509::certificate::Certificate, mbedtls::Error as MbedError, pkix::oid,
    pkix::pem::PEM_CERTIFICATE, pkix::x509::GenericCertificate, pkix::FromBer, std::ops::Deref,
};

use crate::pckcrt::TcbComponents;
use crate::{io, CpuSvn, Error, PceIsvsvn, Platform, TcbStatus, Unverified, VerificationType, Verified};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Fmspc([u8; 6]);

#[derive(Debug)]
pub enum FmspcDecodeError {
    InvalidHex,
    InvalidFmspcLength,
}

impl From<base16::DecodeError> for FmspcDecodeError {
    fn from(_value: base16::DecodeError) -> FmspcDecodeError {
        FmspcDecodeError::InvalidHex
    }
}

impl Fmspc {
    pub const fn new(value: [u8; 6]) -> Self {
        Fmspc(value)
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl From<[u8; 6]> for Fmspc {
    fn from(value: [u8; 6]) -> Fmspc {
        Fmspc::new(value)
    }
}

impl TryFrom<&[u8]> for Fmspc {
    type Error = FmspcDecodeError;

    fn try_from(value: &[u8]) -> Result<Fmspc, FmspcDecodeError> {
        let value = <[u8; 6]>::try_from(value).map_err(|_| FmspcDecodeError::InvalidFmspcLength)?;
        Ok(Fmspc::new(value))
    }
}

impl TryFrom<&Vec<u8>> for Fmspc {
    type Error = FmspcDecodeError;

    fn try_from(value: &Vec<u8>) -> Result<Fmspc, FmspcDecodeError> {
        Fmspc::try_from(value.as_slice())
    }
}

impl TryFrom<&str> for Fmspc {
    type Error = FmspcDecodeError;

    fn try_from(value: &str) -> Result<Fmspc, FmspcDecodeError> {
        let value = base16::decode(value)?;
        Fmspc::try_from(value.as_slice())
    }
}

impl TryFrom<&String> for Fmspc {
    type Error = FmspcDecodeError;

    fn try_from(value: &String) -> Result<Fmspc, FmspcDecodeError> {
        Fmspc::try_from(value.as_str())
    }
}

impl ToString for Fmspc {
    fn to_string(&self) -> String {
        base16::encode_lower(&self.0)
    }
}

impl Serialize for Fmspc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Fmspc {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fmspc = <&str>::deserialize(deserializer)?;
        Fmspc::try_from(fmspc).map_err(|_| de::Error::custom("Bad fmspc format"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    tcb: TcbComponents,
    #[serde(with = "crate::iso8601")]
    tcb_date: DateTime<Utc>,
    tcb_status: TcbStatus,
    #[serde(default, rename = "advisoryIDs", skip_serializing_if = "Vec::is_empty")]
    advisory_ids: Vec<AdvisoryID>,
}

impl TcbLevel {
    pub fn components(&self) -> &TcbComponents {
        &self.tcb
    }

    pub fn tcb_status(&self) -> TcbStatus {
        self.tcb_status
    }

    pub fn advisory_ids(&self) -> &Vec<AdvisoryID> {
        &self.advisory_ids
    }

    pub fn tcb_date(&self) -> &DateTime<Utc> {
        &self.tcb_date
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvisoryID {
    /// Security Advisory ID - "INTEL-SA-XXXXX" (where XXXXX is a placeholder for a 5-digit
    /// number) - representing Security Advisories that can be searched on Intel® Product
    /// Security Center Advisories page
    /// (https://www.intel.com/content/www/us/en/security-center/default.html)
    Security(u32),
    /// Document Advisory ID - "INTEL-DOC-XXXXX" (where XXXXX is a placeholder for a 5-digit
    /// number) - representing articles containing additional information about the attested
    /// platform. The articles can be found under the following URL:
    /// https://api.trustedservices.intel.com/documents/{docID}
    Documentation(u32)
}

impl ToString for AdvisoryID {
    fn to_string(&self) -> String {
        match self {
            AdvisoryID::Security(v) => format!("INTEL-SA-{:05}", v),
            AdvisoryID::Documentation(v) => format!("INTEL-DOC-{:05}", v),
        }
    }
}

impl TryFrom<&str> for AdvisoryID {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<AdvisoryID, &'static str> {
        fn tokenize(s: &str) -> Result<(String, String, u32), &'static str> {
            let mut chunks = s.trim().split('-');

            let intel = chunks.next().ok_or("Couldn't parse INTEL part of advisory ID number")?;
            let typ = chunks.next().ok_or("Couldn't parse type of advisory ID number")?;
            let value = chunks.next().ok_or("Couldn't parse value of advisory ID number")?;
            let value = u32::from_str_radix(value, 10).map_err(|_| "Couldn't parse advisory ID number")?;

            if chunks.next().is_some() {
                return Err("Failed to parse Advisory ID");
            }

            Ok((intel.to_string(), typ.to_string(), value))
        }

        let (intel, typ, value) = tokenize(s)?;
        if intel.to_uppercase() != "INTEL" {
            return Err("Advisory IDs must start with INTEL");
        }

        match typ.to_uppercase().as_str() {
            "SA" => Ok(AdvisoryID::Security(value)),
            "DOC" => Ok(AdvisoryID::Documentation(value)),
            _ => Err("Not a security nor document advisory ID"),
        }
    }
}

impl Serialize for AdvisoryID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AdvisoryID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let advisory = <&str>::deserialize(deserializer)?;
        AdvisoryID::try_from(advisory).map_err(|e| de::Error::custom(format!("Bad AdvisoryID format: {e}")))
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct TcbData<V: VerificationType = Verified> {
    id: Platform,
    version: u16,
    issue_date: DateTime<Utc>,
    next_update: DateTime<Utc>,
    fmspc: Fmspc,
    pce_id: String,
    tcb_type: u16,
    tcb_evaluation_data_number: u64,
    tcb_levels: Vec<TcbLevel>,
    type_: PhantomData<V>,
}

impl<'de> Deserialize<'de> for TcbData<Unverified> {
    fn deserialize<D>(deserializer: D) -> Result<TcbData<Unverified>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Dummy {
            #[serde(default = "crate::sgx_platform")]
            id: Platform,
            version: u16,
            #[serde(with = "crate::iso8601")]
            issue_date: DateTime<Utc>,
            #[serde(with = "crate::iso8601")]
            next_update: DateTime<Utc>,
            fmspc: Fmspc,
            pce_id: String,
            tcb_type: u16,
            tcb_evaluation_data_number: u64,
            #[serde(rename = "tcbLevels")]
            tcb_levels: Vec<TcbLevel>,
        }

        let Dummy {
            id,
            version,
            issue_date,
            next_update,
            fmspc,
            pce_id,
            tcb_type,
            tcb_evaluation_data_number,
            tcb_levels,
        } = Dummy::deserialize(deserializer)?;
        Ok(TcbData {
            id,
            version,
            issue_date,
            next_update,
            fmspc,
            pce_id,
            tcb_type,
            tcb_evaluation_data_number,
            tcb_levels,
            type_: PhantomData,
        })
    }
}

impl TcbData<Verified> {
    pub fn version(&self) -> u16 {
        self.version
    }

    pub fn fmspc(&self) -> &Fmspc {
        &self.fmspc
    }

    pub fn tcb_evaluation_data_number(&self) -> u64 {
        self.tcb_evaluation_data_number
    }
}

impl TcbData<Unverified> {
    fn parse(raw_tcb_data: &String) -> Result<TcbData<Unverified>, Error> {
        let data: TcbData<Unverified> = serde_json::from_str(&raw_tcb_data).map_err(|e| Error::ParseError(e))?;
        if data.version != 2 && data.version != 3 {
            return Err(Error::UnknownTcbInfoVersion(data.version));
        }

        // Only tcb_type 0 is known at the moment, verify that it has that expected value
        if data.tcb_type != 0 {
            return Err(Error::UnknownTcbType(data.tcb_type));
        }
        Ok(data)
    }
}

impl<V: VerificationType> TcbData<V> {
    // NOTE: don't make this publicly available. We want to prevent people from
    // accessing the TCB levels without checking whether the TcbInfo is valid.
    pub(crate) fn tcb_levels(&self) -> &Vec<TcbLevel> {
        &self.tcb_levels
    }

    pub(crate) fn decompose_raw_cpusvn(&self, raw_cpusvn: &[u8; 16], pce_svn: u16) -> Result<TcbComponents, Error> {
        if self.tcb_type != 0 {
            return Err(Error::UnknownTcbType(self.tcb_type));
        }

        // TCB Type 0 simply copies cpu svn
        Ok(TcbComponents::from_raw(*raw_cpusvn, pce_svn))
    }

    pub fn iter_tcb_components(&self) -> impl Iterator<Item = (CpuSvn, PceIsvsvn)> + '_ {
        self.tcb_levels.iter().map(|tcb_level| (tcb_level.tcb.cpu_svn(), tcb_level.tcb.pce_svn()))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct TcbInfo {
    raw_tcb_info: String,
    signature: Vec<u8>,
    ca_chain: Vec<String>,
}

impl TcbInfo {
    pub fn new(raw_tcb_info: String, signature: Vec<u8>, ca_chain: Vec<String>) -> Self {
        TcbInfo {
            raw_tcb_info,
            signature,
            ca_chain,
        }
    }

    pub fn parse(body: &String, ca_chain: Vec<String>) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct IntelTcbInfoSigned<'a> {
            #[serde(borrow, rename = "tcbInfo")]
            raw_tcb_info: &'a RawValue,
            #[serde(deserialize_with = "crate::intel_signature_deserializer")]
            signature: Vec<u8>,
        }
        let IntelTcbInfoSigned { raw_tcb_info, signature } = serde_json::from_str(&body)?;

        Ok(TcbInfo::new(raw_tcb_info.to_string(), signature, ca_chain))
    }

    pub fn create_filename(fmspc: &str, evaluation_data_number: Option<u64>) -> String {
        if let Some(evaluation_data_number) = evaluation_data_number {
            format!("{fmspc}-{evaluation_data_number}.tcb")
        } else {
            format!("{fmspc}.tcb")
        }
    }

    pub fn store(&self, output_dir: &str) -> Result<String, Error> {
        let data = TcbData::<Unverified>::parse(&self.raw_tcb_info)?;
        let filename = Self::create_filename(&data.fmspc.to_string(), Some(data.tcb_evaluation_data_number));
        io::write_to_file(&self, output_dir, &filename)?;
        Ok(filename)
    }

    pub fn store_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        let data = TcbData::<Unverified>::parse(&self.raw_tcb_info)?;
        let filename = Self::create_filename(&data.fmspc.to_string(), Some(data.tcb_evaluation_data_number));
        io::write_to_file_if_not_exist(&self, output_dir, &filename)
    }

    pub fn restore(input_dir: &str, fmspc: &Fmspc, evaluation_data_number: Option<u64>) -> Result<Self, Error> {
        let filename = TcbInfo::create_filename(&fmspc.to_string(), evaluation_data_number);
        let info: TcbInfo = io::read_from_file(input_dir, &filename)?;
        Ok(info)
    }

    pub fn raw_tcb_info(&self) -> &String {
        &self.raw_tcb_info
    }

    pub fn signature(&self) -> &Vec<u8> {
        &self.signature
    }

    pub fn certificate_chain(&self) -> &Vec<String> {
        &self.ca_chain
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], platform: Platform, min_version: u16) -> Result<TcbData<Verified>, Error> {
        let now = Utc::now();
        self.verify_ex(trusted_root_certs, platform, min_version, &now)
    }

    #[cfg(feature = "verify")]
    fn verify_ex<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], platform: Platform, min_version: u16, now: &DateTime<Utc>) -> Result<TcbData<Verified>, Error> {
        // Check cert chain
        let (chain, root) = crate::create_cert_chain(&self.ca_chain)?;
        let mut leaf = chain.first().unwrap_or(&root).clone();
        let root_list = std::iter::once(root).collect();
        if 0 < chain.len() {
            let trust_ca: MbedtlsList<Certificate> = chain.into_iter().collect();
            let mut err = String::default();
            Certificate::verify(&trust_ca, &root_list, None, Some(&mut err))
                .map_err(|_| Error::InvalidTcbInfo(format!("Invalid TcbInfo: {}", err)))?;
        }

        // Check signature on data
        let mut hash = [0u8; 32];
        mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, self.raw_tcb_info.as_bytes(), &mut hash).unwrap();
        leaf.public_key_mut()
            .verify(mbedtls::hash::Type::Sha256, &hash, self.signature())
            .map_err(|_| Error::InvalidTcbInfo("Signature verification failed".into()))?;

        // Check common name TCB cert
        let leaf = self.ca_chain.first().ok_or(Error::IncorrectCA)?;
        let tcb =
            &pkix::pem::pem_to_der(&leaf, Some(PEM_CERTIFICATE)).ok_or(Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        let tcb = GenericCertificate::from_ber(&tcb).map_err(|_| Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        let name = tcb
            .tbscert
            .subject
            .get(&*oid::commonName)
            .ok_or(Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        if String::from_utf8_lossy(&name.value()) != "Intel SGX TCB Signing" {
            return Err(Error::IncorrectCA);
        }

        crate::check_root_ca(trusted_root_certs, &root_list)?;

        let TcbData {
            id,
            version,
            issue_date,
            next_update,
            fmspc,
            pce_id,
            tcb_type,
            tcb_evaluation_data_number,
            tcb_levels,
            ..
        } = TcbData::parse(&self.raw_tcb_info)?;

        if id != platform {
            return Err(Error::InvalidTcbInfo(format!("TCB Info belongs to the {id} platform, expected one for the {platform} platform")))
        }

        if min_version > version {
            return Err(Error::UntrustedTcbInfoVersion(version, min_version))
        }

        if *now < issue_date {
            return Err(Error::InvalidTcbInfo(format!("TCB Info only valid from {}", issue_date)))
        }
        if next_update < *now {
            return Err(Error::InvalidTcbInfo(format!("TCB Info expired on {}", next_update)))
        }

        Ok(TcbData::<Verified> {
            id,
            version,
            issue_date,
            next_update,
            fmspc,
            pce_id,
            tcb_type,
            tcb_evaluation_data_number,
            tcb_levels,
            type_: PhantomData,
        })
    }

    pub fn data(&self) -> Result<TcbData<Unverified>, Error> {
        TcbData::parse(&self.raw_tcb_info)
    }
}

#[cfg(feature = "verify")]
#[cfg(test)]
mod tests {
    #[cfg(not(target_env = "sgx"))]
    use {
        crate::Error,
        crate::tcb_info::{Fmspc, Platform, TcbInfo},
        std::convert::TryFrom,
        tempdir::TempDir,
    };
    use super::AdvisoryID;
    use chrono::{Utc, TimeZone};
    use std::assert_matches::assert_matches;

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_tcb_info() {
        let info =
            TcbInfo::restore("./tests/data/", &Fmspc::try_from("00906ea10000").expect("static fmspc"), None).expect("validated");
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        match info.verify(&root_certificates, Platform::SGX, 2) {
            Err(Error::InvalidTcbInfo(msg)) => assert_eq!(msg, String::from("TCB Info expired on 2020-06-17 17:49:24 UTC")),
            e => assert!(false, "wrong result: {:?}", e),
        }
        let juni_5_2020 = Utc.with_ymd_and_hms(2020, 6, 5, 12, 0, 0).unwrap();
        assert!(info.verify_ex(&root_certificates, Platform::SGX, 2, &juni_5_2020).is_ok());

        match info.verify(&root_certificates, Platform::TDX, 2) {
            Err(Error::InvalidTcbInfo(msg)) => assert_eq!(msg, String::from("TCB Info belongs to the SGX platform, expected one for the TDX platform")),
            e => assert!(false, "wrong result: {:?}", e),
        }

        // Test serialization/deserialization
        let temp_dir = TempDir::new("tempdir").unwrap();
        let path = temp_dir.path().as_os_str().to_str().unwrap();
        info.store(&path).unwrap();
        let info2 = TcbInfo::restore(&path, &Fmspc::try_from("00906ea10000").expect("static fmspc"), Some(8)).unwrap();
        assert_eq!(info, info2);
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_corrupt_tcb_info() {
        let tcb_info = TcbInfo::restore("./tests/data/corrupted", &Fmspc::try_from("00906ea10000").unwrap(), None).unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        assert!(tcb_info.verify(&root_certificates, Platform::SGX, 2).is_err());
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_tcb_info_v3() {
        let tcb_info = TcbInfo::restore("./tests/data/", &Fmspc::try_from("00906ed50000").unwrap(), Some(18)).unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        let april_28_2025 = Utc.with_ymd_and_hms(2025, 4, 28, 12, 0, 0).unwrap();
        assert!(tcb_info.verify_ex(&root_certificates, Platform::SGX, 3, &april_28_2025).is_ok());
        assert_matches!(tcb_info.verify_ex(&root_certificates, Platform::SGX, 4, &april_28_2025), Err(Error::UntrustedTcbInfoVersion(3, 4)));
    }

    #[test]
    fn parse_advisory_ids() {
        assert_eq!(AdvisoryID::try_from("INTEL-SA-00123"), Ok(AdvisoryID::Security(123)));
        assert_eq!(AdvisoryID::try_from("INTEL-SA-10123"), Ok(AdvisoryID::Security(10123)));
        assert_eq!(AdvisoryID::try_from("INTEL-SA-00001"), Ok(AdvisoryID::Security(1)));
        assert_eq!(AdvisoryID::try_from("INTEL-DOC-00123"), Ok(AdvisoryID::Documentation(123)));
        assert_eq!(AdvisoryID::try_from("INTEL-DOC-10123"), Ok(AdvisoryID::Documentation(10123)));
        assert_eq!(AdvisoryID::try_from("INTEL-DOC-00001"), Ok(AdvisoryID::Documentation(1)));
    }

    #[test]
    fn advisory_ids_to_string() {
        assert_eq!(AdvisoryID::Security(123).to_string(), "INTEL-SA-00123");
        assert_eq!(AdvisoryID::Security(1).to_string(), "INTEL-SA-00001");
        assert_eq!(AdvisoryID::Security(99999).to_string(), "INTEL-SA-99999");
        assert_eq!(AdvisoryID::Documentation(123).to_string(), "INTEL-DOC-00123");
        assert_eq!(AdvisoryID::Documentation(1).to_string(), "INTEL-DOC-00001");
        assert_eq!(AdvisoryID::Documentation(99999).to_string(), "INTEL-DOC-99999");
    }
}
