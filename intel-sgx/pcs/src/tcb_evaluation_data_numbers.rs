
use chrono::{DateTime, Utc};
use crate::{io, Error, Platform, Unverified, VerificationType, Verified};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::marker::PhantomData;

#[cfg(feature = "verify")]
use {
    mbedtls::alloc::List as MbedtlsList, mbedtls::x509::certificate::Certificate, mbedtls::Error as MbedError, pkix::oid,
    pkix::pem::PEM_CERTIFICATE, pkix::x509::GenericCertificate, pkix::FromBer, std::ops::Deref,
};

/// Implementation of the TcbEvaluationDataNumbers model
/// <https://api.portal.grustedservices.intel.com/content/documentation.html#pcs-tcb-eval-data-numbers-model-v1>
#[derive(Clone, Debug)]
pub struct TcbEvaluationDataNumbers<V: VerificationType = Verified> {
    #[allow(unused)]
    id: Platform,
    #[allow(unused)]
    version: u16,
    #[allow(unused)]
    issue_date: DateTime<Utc>,
    #[allow(unused)]
    next_update: DateTime<Utc>,
    #[allow(unused)]
    tcb_eval_numbers: Vec<TcbEvalNumber>,
    type_: PhantomData<V>,
}

impl<'de> Deserialize<'de> for TcbEvaluationDataNumbers<Unverified> {
    fn deserialize<D>(deserializer: D) -> Result<TcbEvaluationDataNumbers<Unverified>, D::Error>
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
            tcb_eval_numbers: Vec<TcbEvalNumber>
        }

        let Dummy {
            id,
            version,
            issue_date,
            next_update,
            tcb_eval_numbers,
        } = Dummy::deserialize(deserializer)?;
        Ok(TcbEvaluationDataNumbers {
            id,
            version,
            issue_date,
            next_update,
            tcb_eval_numbers,
            type_: PhantomData,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbEvalNumber {
    #[serde(rename = "tcbEvaluationDataNumber")]
    number: u16,
    #[serde(with = "crate::iso8601")]
    tcb_recovery_event_date: DateTime<Utc>,
    #[serde(with = "crate::iso8601")]
    tcb_date: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct RawTcbEvaluationDataNumbers {
    raw_tcb_evaluation_data_numbers: String,
    signature: Vec<u8>,
    ca_chain: Vec<String>,
}

impl RawTcbEvaluationDataNumbers {
    const DEFAULT_FILENAME: &'static str = "tcb_evaluation_data_numbers.numbers";

    pub fn new(raw_tcb_evaluation_data_numbers: String, signature: Vec<u8>, ca_chain: Vec<String>) -> Self {
        RawTcbEvaluationDataNumbers {
            raw_tcb_evaluation_data_numbers,
            signature,
            ca_chain,
        }
    }

    pub fn parse(body: &String, ca_chain: Vec<String>) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct IntelTcbEvaluationDataNumbers<'a> {
            #[serde(borrow, rename = "tcbEvaluationDataNumbers")]
            raw_tcb_evaluation_data_numbers: &'a RawValue,
            #[serde(deserialize_with = "crate::intel_signature_deserializer")]
            signature: Vec<u8>,
        }
        let IntelTcbEvaluationDataNumbers { raw_tcb_evaluation_data_numbers, signature } = serde_json::from_str(&body)?;

        Ok(RawTcbEvaluationDataNumbers::new(raw_tcb_evaluation_data_numbers.to_string(), signature, ca_chain))
    }

    pub fn signature(&self) -> &Vec<u8> {
        &self.signature
    }

    pub fn certificate_chain(&self) -> &Vec<String> {
        &self.ca_chain
    }

    pub fn write_to_file(&self, output_dir: &str) -> Result<String, Error> {
        io::write_to_file(&self, output_dir, Self::DEFAULT_FILENAME)?;
        Ok(Self::DEFAULT_FILENAME.to_string())
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let identity: Self = io::read_from_file(input_dir, Self::DEFAULT_FILENAME)?;
        Ok(identity)
    }

    /// Returns a Vec of the TCB evaluation data numbers present. Warning: These values should not
    /// be trusted as there is no guarantee the RawTcbEvaluationDataNumbers is valid. If this
    /// result must be trustworthy, you need to call `verify` and inspect the
    /// `TcbEvaluationDataNumbers`
    pub fn evaluation_data_numbers(&self) -> Result<Vec<u16>, Error> {
        let TcbEvaluationDataNumbers::<Unverified> {
            tcb_eval_numbers,
            ..
        } = serde_json::from_str(&self.raw_tcb_evaluation_data_numbers).map_err(|e| Error::ParseError(e))?;
        Ok(tcb_eval_numbers.iter().map(|tcb_eval| tcb_eval.number).collect())
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], platform: Platform) -> Result<TcbEvaluationDataNumbers, Error> {
        // Check cert chain
        let (chain, root) = crate::create_cert_chain(&self.ca_chain)?;
        let mut leaf = chain.first().unwrap_or(&root).clone();
        let root_list = std::iter::once(root).collect();
        if 0 < chain.len() {
            let trust_ca: MbedtlsList<Certificate> = chain.into_iter().collect();
            let mut err = String::default();
            Certificate::verify(&trust_ca, &root_list, None, Some(&mut err))
                .map_err(|e| Error::UntrustworthyTcbEvaluationDataNumber(e))?;
        }

        // Check signature on data
        let mut hash = [0u8; 32];
        mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, self.raw_tcb_evaluation_data_numbers.as_bytes(), &mut hash).unwrap();
        leaf.public_key_mut()
            .verify(mbedtls::hash::Type::Sha256, &hash, self.signature())
            .map_err(|e| Error::UntrustworthyTcbEvaluationDataNumber(e))?;

        // Check common name TCB cert
        let leaf = self.ca_chain.first().ok_or(Error::IncorrectCA)?;
        let tcb =
            &pkix::pem::pem_to_der(&leaf, Some(PEM_CERTIFICATE)).ok_or(Error::UntrustworthyTcbEvaluationDataNumber(MbedError::X509BadInputData))?;
        let tcb = GenericCertificate::from_ber(&tcb).map_err(|_| Error::UntrustworthyTcbEvaluationDataNumber(MbedError::X509BadInputData))?;
        let name = tcb
            .tbscert
            .subject
            .get(&*oid::commonName)
            .ok_or(Error::UntrustworthyTcbEvaluationDataNumber(MbedError::X509BadInputData))?;
        if String::from_utf8_lossy(&name.value()) != "Intel SGX TCB Signing" {
            return Err(Error::IncorrectCA);
        }

        crate::check_root_ca(trusted_root_certs, &root_list)?;

        let TcbEvaluationDataNumbers::<Unverified> {
            id,
            version,
            issue_date,
            next_update,
            tcb_eval_numbers,
            ..
        } = serde_json::from_str(&self.raw_tcb_evaluation_data_numbers).map_err(|e| Error::ParseError(e))?;

        if version != 1 {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers version 1 expected, got {version}")));
        }

        if id != platform {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid for {id}, expected one for {platform}")));
        }

        let now = Utc::now();
        if now < issue_date {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid from {issue_date}")));
        }
        if next_update < now {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid from {next_update}")));
        }

        Ok(TcbEvaluationDataNumbers::<Verified> {
            id,
            version,
            issue_date,
            next_update,
            tcb_eval_numbers,
            type_: PhantomData,
        })
    }
}

#[cfg(all(not(target_env = "sgx"), feature = "verify"))]
#[cfg(test)]
mod tests {
    use super::RawTcbEvaluationDataNumbers;
    use crate::{Error, Platform};

    #[test]
    fn parse_tcb_evaluation_data_numbers() {
        let numbers = RawTcbEvaluationDataNumbers::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        numbers.verify(&root_certificates, Platform::SGX).unwrap();
    }

    #[test]
    fn parse_tcb_evaluation_data_numbers_incorrect_signature() {
        let numbers = RawTcbEvaluationDataNumbers::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert").to_owned();
        let root_certificates = [&root_certificate[..]];
        numbers.verify(&root_certificates, Platform::SGX).unwrap();

        let mut corrupted = numbers.clone();
        corrupted.signature[10] = 0x66;
        if let Err(Error::UntrustworthyTcbEvaluationDataNumber(_s)) = corrupted.verify(&root_certificates, Platform::SGX) {
            ();
        } else {
            assert!(false);
        }
    }
}

