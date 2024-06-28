use std::marker::PhantomData;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::List as MbedtlsList, mbedtls::x509::certificate::Certificate, mbedtls::Error as MbedError, pkix::oid,
    pkix::pem::PEM_CERTIFICATE, pkix::x509::GenericCertificate, pkix::FromBer, std::ops::Deref,
};

use crate::pckcrt::TcbComponents;
use crate::{io, Error, TcbStatus, Unverified, VerificationType, Verified};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: TcbComponents,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(default, rename = "advisoryIDs", skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Platform {
    SGX,
    TDX,
}

fn sgx_platform() -> Platform {
    Platform::SGX
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TcbData<V: VerificationType = Verified> {
    #[serde(default = "sgx_platform")]
    id: Platform,
    version: u16,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u16,
    tcb_evaluation_data_number: u64,
    #[serde(rename = "tcbLevels")]
    tcb_levels: Vec<TcbLevel>,
    #[serde(skip)]
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
            #[serde(default = "sgx_platform")]
            id: Platform,
            version: u16,
            issue_date: String,
            next_update: String,
            fmspc: String,
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
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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

    fn create_filename(fmspc: &str) -> String {
        format!("{}.tcb", fmspc)
    }

    pub fn store(&self, output_dir: &str) -> Result<String, Error> {
        let data = TcbData::<Unverified>::parse(&self.raw_tcb_info)?;
        let filename = Self::create_filename(&data.fmspc);
        io::write_to_file(&self, output_dir, &filename)?;
        Ok(filename)
    }

    pub fn store_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        let data = TcbData::<Unverified>::parse(&self.raw_tcb_info)?;
        let filename = Self::create_filename(&data.fmspc);
        io::write_to_file_if_not_exist(&self, output_dir, &filename)
    }

    pub fn restore(input_dir: &str, fmspc: &[u8]) -> Result<Self, Error> {
        let fmspc = &base16::encode_lower(&fmspc);
        let filename = TcbInfo::create_filename(fmspc);
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
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B]) -> Result<TcbData<Verified>, Error> {
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
    use crate::tcb_info::TcbInfo;

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_tcb_info() {
        let info = TcbInfo::restore(
            "./tests/data/",
            &base16::decode("00906ea10000".as_bytes()).expect("validated"),
        )
        .expect("validated");
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        assert!(info.verify(&root_certificates).is_ok());
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_corrupt_tcb_info() {
        let tcb_info = TcbInfo::restore("./tests/data/corrupted", &base16::decode("00906ea10000".as_bytes()).unwrap()).unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        assert!(tcb_info.verify(&root_certificates).is_err());
    }
}
