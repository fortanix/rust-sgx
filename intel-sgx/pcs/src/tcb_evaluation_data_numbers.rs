use chrono::{DateTime, Duration, Utc};
use crate::{io, Error, Platform, Unverified, VerificationType, Verified};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::slice::Iter;

#[cfg(feature = "verify")]
use {
    mbedtls::alloc::List as MbedtlsList, mbedtls::x509::certificate::Certificate, mbedtls::error::{codes, Error as ErrMbed}, pkix::oid,
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

impl<V: VerificationType> TcbEvaluationDataNumbers<V> {
    pub fn numbers(&self) -> Iter<'_, TcbEvalNumber> {
        self.tcb_eval_numbers.iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbEvalNumber {
    #[serde(rename = "tcbEvaluationDataNumber")]
    number: u16,
    #[serde(with = "crate::iso8601")]
    tcb_recovery_event_date: DateTime<Utc>,
    #[serde(with = "crate::iso8601")]
    tcb_date: DateTime<Utc>,
}

impl TcbEvalNumber {
    pub fn number(&self) -> u16 {
        self.number
    }

    pub fn tcb_recovery_event_date(&self) -> &DateTime<Utc> {
        &self.tcb_recovery_event_date
    }

    pub fn tcb_date(&self) -> &DateTime<Utc> {
        &self.tcb_date
    }
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

    pub fn filename() -> String {
        Self::DEFAULT_FILENAME.into()
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

    /// Returns the raw TCB evaluation data numbers as signed by Intel
    pub fn raw_tcb_evaluation_data_numbers(&self) -> &str {
        &self.raw_tcb_evaluation_data_numbers
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

    pub fn write_to_file_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        io::write_to_file_if_not_exist(&self, output_dir, Self::DEFAULT_FILENAME)
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let identity: Self = io::read_from_file(input_dir, Self::DEFAULT_FILENAME)?;
        Ok(identity)
    }

    /// Returns the TCB evaluation data numbers present. Warning: These values should not
    /// be trusted as there is no guarantee the RawTcbEvaluationDataNumbers is valid. If this
    /// result must be trustworthy, you need to call `verify`
    pub fn evaluation_data_numbers(&self) -> Result<TcbEvaluationDataNumbers<Unverified>, Error> {
        serde_json::from_str(&self.raw_tcb_evaluation_data_numbers).map_err(|e| Error::ParseError(e))
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], platform: Platform) -> Result<TcbEvaluationDataNumbers, Error> {
        self.verify_ex(trusted_root_certs, platform, &Utc::now())
    }

    #[cfg(feature = "verify")]
    fn verify_ex<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], platform: Platform, now: &DateTime<Utc>) -> Result<TcbEvaluationDataNumbers, Error> {
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
            &pkix::pem::pem_to_der(&leaf, Some(PEM_CERTIFICATE)).ok_or(Error::UntrustworthyTcbEvaluationDataNumber(ErrMbed::HighLevel(codes::X509BadInputData)))?;
        let tcb = GenericCertificate::from_ber(&tcb).map_err(|_| Error::UntrustworthyTcbEvaluationDataNumber(ErrMbed::HighLevel(codes::X509BadInputData)))?;
        let name = tcb
            .tbscert
            .subject
            .get(&*oid::commonName)
            .ok_or(Error::UntrustworthyTcbEvaluationDataNumber(ErrMbed::HighLevel(codes::X509BadInputData)))?;
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

        if *now < issue_date {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid from {issue_date}")));
        }
        if next_update < *now {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid upto {next_update}")));
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbPolicy {
    grace_period: Duration,
}

impl TcbPolicy {
    /// A TCB policy that allows for TCB info to be used until `grace_period` after
    /// a TCB recovery event
    pub const fn new(grace_period: Duration) -> Self {
        Self {
            grace_period
        }
    }

    fn needs_to_be_enforced(&self, tcb_eval: &TcbEvalNumber, now: &DateTime<Utc>) -> bool {
        *tcb_eval.tcb_recovery_event_date() + self.grace_period <= *now
    }

    fn minimum_tcb_evaluation_data_number_ex<V: VerificationType>(&self, tcb_eval: &TcbEvaluationDataNumbers<V>, now: &DateTime<Utc>) -> Option<TcbEvalNumber> {
        tcb_eval.numbers().fold(None, |last, number| {
            match (last, self.needs_to_be_enforced(number, &now)) {
                (last, false) => last,
                (Some(last), true) => {
                    if last.number() <= number.number() {
                        // We need the highest TCB Eval Data Number that needs to be enforced
                        Some(number.clone())
                    } else {
                        Some(last)
                    }
                },
                (None, true)  => Some(number.clone()),
            }
        })
    }

    pub fn minimum_tcb_evaluation_data_number<V: VerificationType>(&self, tcb_eval: &TcbEvaluationDataNumbers<V>) -> Option<TcbEvalNumber> {
        self.minimum_tcb_evaluation_data_number_ex(tcb_eval, &Utc::now())
    }
}

#[cfg(all(not(target_env = "sgx"), feature = "verify"))]
#[cfg(test)]
mod tests {
    use super::{RawTcbEvaluationDataNumbers, TcbEvaluationDataNumbers, TcbEvalNumber, TcbPolicy};
    use crate::{Error, Platform, Unverified};
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn parse_tcb_evaluation_data_numbers() {
        let numbers = RawTcbEvaluationDataNumbers::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        numbers.verify_ex(&root_certificates, Platform::SGX, &Utc.with_ymd_and_hms(2025, 4, 1, 12, 0, 0).unwrap()).unwrap();
    }

    #[test]
    fn parse_tcb_evaluation_data_numbers_incorrect_signature() {
        let numbers = RawTcbEvaluationDataNumbers::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert").to_owned();
        let root_certificates = [&root_certificate[..]];
        numbers.verify_ex(&root_certificates, Platform::SGX, &Utc.with_ymd_and_hms(2025, 4, 1, 12, 0, 0).unwrap()).unwrap();

        let mut corrupted = numbers.clone();
        corrupted.signature[10] = 0x66;
        if let Err(Error::UntrustworthyTcbEvaluationDataNumber(_s)) = corrupted.verify(&root_certificates, Platform::SGX) {
            ();
        } else {
            assert!(false);
        }
    }

    #[test]
    fn tcb_eval_number() {
        let april_8_2025 = Utc.with_ymd_and_hms(2025, 4, 8, 14, 55, 0).unwrap();
        let april_9_2025 = Utc.with_ymd_and_hms(2025, 4, 9, 14, 55, 0).unwrap();
        let april_15_2025 = Utc.with_ymd_and_hms(2025, 4, 15, 14, 55, 0).unwrap();
        let april_16_2025 = Utc.with_ymd_and_hms(2025, 4, 16, 14, 55, 0).unwrap();
        let april_17_2025 = Utc.with_ymd_and_hms(2025, 4, 17, 14, 55, 0).unwrap();
        let number = TcbEvalNumber {
            number: 42,
            tcb_recovery_event_date: april_9_2025,
            tcb_date: april_9_2025,
        };

        let policy = TcbPolicy::new(Duration::days(8));
        assert!(!policy.needs_to_be_enforced(&number, &april_8_2025));
        assert!(!policy.needs_to_be_enforced(&number, &april_9_2025));
        assert!(!policy.needs_to_be_enforced(&number, &april_15_2025));
        assert!(!policy.needs_to_be_enforced(&number, &april_16_2025));
        assert!(policy.needs_to_be_enforced(&number, &april_17_2025));
    }

    #[test]
    fn minimum_tcb_evaluation_data_number() {
        let numbers = RawTcbEvaluationDataNumbers::read_from_file("./tests/data").unwrap();
        let numbers: TcbEvaluationDataNumbers<Unverified> = serde_json::from_str(numbers.raw_tcb_evaluation_data_numbers()).unwrap();

        let april_8_2025 = Utc.with_ymd_and_hms(2025, 4, 8, 0, 0, 0).unwrap();
        let march_12_2024 = Utc.with_ymd_and_hms(2024, 3, 12, 0, 0, 0).unwrap();
        let march_13_2024 = Utc.with_ymd_and_hms(2024, 3, 13, 0, 0, 0).unwrap();
        let november_12_2024 = Utc.with_ymd_and_hms(2024, 11, 12, 0, 0, 0).unwrap();
        let november_13_2024 = Utc.with_ymd_and_hms(2024, 11, 13, 0, 0, 0).unwrap();
        let november_20_2024 = Utc.with_ymd_and_hms(2024, 11, 20, 0, 0, 0).unwrap();
        let number_17 = TcbEvalNumber {
            number: 17,
            tcb_recovery_event_date: march_12_2024,
            tcb_date: march_13_2024,
        };
        let number_18 = TcbEvalNumber {
            number: 18,
            tcb_recovery_event_date: november_12_2024,
            tcb_date: november_13_2024,
        };
        let policy = TcbPolicy::new(Duration::days(10));
        assert_eq!(policy.minimum_tcb_evaluation_data_number_ex(&numbers, &april_8_2025),
            Some(number_18));
        assert_eq!(policy.minimum_tcb_evaluation_data_number_ex(&numbers, &november_13_2024),
            Some(number_17.clone()));
        assert_eq!(policy.minimum_tcb_evaluation_data_number_ex(&numbers, &november_20_2024),
            Some(number_17));
    }
}
