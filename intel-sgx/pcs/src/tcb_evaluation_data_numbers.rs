use chrono::{DateTime, Duration, Utc};
use crate::{
    Error, Fmspc, PlatformTypeForTcbInfo, QeIdentity, QeIdentitySigned, TcbData, TcbInfo, TcbStatus,
    Unverified, VerificationType, Verified, io::{self, WriteOptions}, pckcrt::TcbComponents
};
use serde::{Deserialize, Serialize};
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
/// <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-eval-data-numbers-model-v1>
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbEvaluationDataNumbers<T: PlatformTypeForTcbInfo, V: VerificationType = Verified> {
    #[allow(unused)]
    #[serde(deserialize_with = "crate::deserialize_platform_id")]
    id: T,
    #[allow(unused)]
    version: u16,
    #[allow(unused)]
    #[serde(with = "crate::iso8601")]
    issue_date: DateTime<Utc>,
    #[allow(unused)]
    #[serde(with = "crate::iso8601")]
    next_update: DateTime<Utc>,
    #[allow(unused)]
    tcb_eval_numbers: Vec<TcbEvalNumber>,
    _type: V,
}

impl<T: PlatformTypeForTcbInfo, V: VerificationType> TcbEvaluationDataNumbers<T, V> {
    pub fn numbers(&self) -> Iter<'_, TcbEvalNumber> {
        self.tcb_eval_numbers.iter()
    }
}

impl<T: PlatformTypeForTcbInfo> TcbEvaluationDataNumbers<T, Unverified> {
    /// Given a particular TCB level, select the best available TCB eval number.
    /// That is the one that gives the most favorable TCB status, and the higher
    /// one if there's a tie.
    pub fn select_best(input_dir: &str, fmspc: &Fmspc, tcb_components: &TcbComponents<T::PlatformSpecificTcbComponentData>, qesvn: u16) -> Result<TcbEvalNumber, Error> {
        let evalnums = RawTcbEvaluationDataNumbers::<T>::read_from_file(input_dir)?.evaluation_data_numbers()?;
        let mut tcb_levels: std::collections::HashMap<_, _> = evalnums.numbers().map(|num| (num.number as u64, (num, None, None))).collect();

        for tcbinfo in TcbInfo::<T>::read_all(input_dir, fmspc) {
            let tcb_data: TcbData<T, Unverified> = TcbData::parse(tcbinfo?.raw_tcb_info())?;
            if let Some(level) = tcb_data.tcb_levels()
                .iter()
                .find(|level| level.tcb <= *tcb_components)
            {
                if let Some(entry) = tcb_levels.get_mut(&tcb_data.tcb_evaluation_data_number()) {
                    entry.1 = Some(level.tcb_status);
                }
            }
        };

        for qeid in QeIdentitySigned::read_all(input_dir) {
            let qeid: QeIdentity::<Unverified> = serde_json::from_str(&qeid?.raw_qe_identity()).map_err(|e| Error::ParseError(e))?;
            if let Some(level) = qeid.tcb_levels()
                .iter()
                .find(|level| level.tcb.isvsvn <= qesvn)
            {
                if let Some(entry) = tcb_levels.get_mut(&qeid.tcb_evaluation_data_number()) {
                    entry.2 = Some(level.tcb_status);
                }
            }
        };

        // NB: QE Identity TCB status can only be UpToDate, OutOfDate, or Revoked
        fn tcb_total_order(platform_status: Option<TcbStatus>, qe_status: Option<TcbStatus>) -> i8 {
            use std::ops::Neg;
            use self::TcbStatus::*;
            // Since we don't have any information here to judge the enclave
            // has the needed SW hardening, we assume that it does and we
            // upgrade SWHardeningNeeded to the next level
            match (platform_status.map(TcbStatus::drop_sw_hardening_needed), qe_status) {
                (Some(UpToDate),                          Some(UpToDate))  => 0i8,
                (Some(UpToDate),                          Some(OutOfDate)) => 1,
                (Some(UpToDate),                          Some(Revoked))   => 1,
                (Some(ConfigurationNeeded),               Some(UpToDate))  => 2,
                (Some(ConfigurationNeeded),               Some(OutOfDate)) => 3,
                (Some(ConfigurationNeeded),               Some(Revoked))   => 3,
                (Some(OutOfDate),                         Some(UpToDate))  => 4,
                (Some(OutOfDateConfigurationNeeded),      Some(UpToDate))  => 4,
                (Some(Revoked),                           Some(UpToDate))  => 4,
                (Some(OutOfDate),                         Some(OutOfDate)) => 5,
                (Some(OutOfDate),                         Some(Revoked))   => 5,
                (Some(Revoked),                           Some(OutOfDate)) => 5,
                (Some(Revoked),                           Some(Revoked))   => 5,
                (Some(OutOfDateConfigurationNeeded),      Some(OutOfDate)) => 5,
                (Some(OutOfDateConfigurationNeeded),      Some(Revoked))   => 5,
                (Some(UpToDate),                          None)            => 6,
                (Some(ConfigurationNeeded),               None)            => 7,
                (Some(OutOfDate),                         None)            => 8,
                (Some(OutOfDateConfigurationNeeded),      None)            => 8,
                (Some(Revoked),                           None)            => 8,
                (None,                                    Some(UpToDate))  => 9,
                (None,                                    Some(OutOfDate)) => 10,
                (None,                                    Some(Revoked))   => 10,
                _                                                          => 11,
            }.neg()
        }

        tcb_levels.into_iter()
            .max_by(|&(a_num, (_, a_platform_status, a_qe_status)), &(b_num, (_, b_platform_status, b_qe_status))| {
                tcb_total_order(a_platform_status, a_qe_status)
                    .cmp(&tcb_total_order(b_platform_status, b_qe_status))
                    .then_with(|| a_num.cmp(&b_num) )
            })
            .map(|(_, (num, _, _))| num.clone())
            .ok_or(Error::InvalidTcbEvaluationDataNumbers("Empty TCB evaluation data numbers".into()))
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
pub struct RawTcbEvaluationDataNumbers<T> {
    raw_tcb_evaluation_data_numbers: String,
    signature: Vec<u8>,
    ca_chain: Vec<String>,
    #[serde(skip)]
    platform_: PhantomData<T>,
}

impl<T: PlatformTypeForTcbInfo> RawTcbEvaluationDataNumbers<T> {
    const DEFAULT_FILENAME: &'static str = "tcb_evaluation_data_numbers";
    const FILENAME_EXTENSION: &'static str = ".numbers";

    pub fn new(raw_tcb_evaluation_data_numbers: String, signature: Vec<u8>, ca_chain: Vec<String>) -> Self {
        RawTcbEvaluationDataNumbers {
            raw_tcb_evaluation_data_numbers,
            signature,
            ca_chain,
            platform_: PhantomData,
        }
    }

    pub fn filename() -> String {
        format!("{}{}{}", Self::DEFAULT_FILENAME, T::extra_extension(), Self::FILENAME_EXTENSION)
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

    pub fn write_to_file(&self, output_dir: &str, option: WriteOptions) -> Result<Option<PathBuf>, Error> {
        let filename = Self::filename();
        io::write_to_file(&self, output_dir, &filename, option)
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let filename = Self::filename();
        let numbers: Self = io::read_from_file(input_dir, &filename)?;
        Ok(numbers)
    }

    /// Returns the TCB evaluation data numbers present. Warning: These values should not
    /// be trusted as there is no guarantee the RawTcbEvaluationDataNumbers is valid. If this
    /// result must be trustworthy, you need to call `verify`
    pub fn evaluation_data_numbers(&self) -> Result<TcbEvaluationDataNumbers<T, Unverified>, Error> {
        serde_json::from_str(&self.raw_tcb_evaluation_data_numbers).map_err(|e| Error::ParseError(e))
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B]) -> Result<TcbEvaluationDataNumbers<T>, Error> {
        self.verify_ex(trusted_root_certs, &Utc::now())
    }

    #[cfg(feature = "verify")]
    fn verify_ex<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B], now: &DateTime<Utc>) -> Result<TcbEvaluationDataNumbers<T>, Error> {
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

        let TcbEvaluationDataNumbers::<T, Unverified> {
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

        if *now < issue_date {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid from {issue_date}")));
        }
        if next_update < *now {
            return Err(Error::InvalidTcbEvaluationDataNumbers(format!("TCB Evaluation Data Numbers only valid upto {next_update}")));
        }

        Ok(TcbEvaluationDataNumbers::<T, Verified> {
            id,
            version,
            issue_date,
            next_update,
            tcb_eval_numbers,
            _type: Verified,
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

    fn minimum_tcb_evaluation_data_number_ex<T: PlatformTypeForTcbInfo, V: VerificationType>(&self, tcb_eval: &TcbEvaluationDataNumbers<T, V>, now: &DateTime<Utc>) -> Option<TcbEvalNumber> {
        // We need the highest TCB Eval Data Number that needs to be enforced
        tcb_eval.numbers()
            .filter(|number| self.needs_to_be_enforced(number, now))
            .max_by_key(|number| number.number)
            .cloned()
    }

    pub fn minimum_tcb_evaluation_data_number<T: PlatformTypeForTcbInfo, V: VerificationType>(&self, tcb_eval: &TcbEvaluationDataNumbers<T, V>) -> Option<TcbEvalNumber> {
        self.minimum_tcb_evaluation_data_number_ex(tcb_eval, &Utc::now())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_env = "sgx"))]
    use {
        super::TcbEvaluationDataNumbers,
        crate::{Error, Unverified, platform}
    };
    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    use super::{RawTcbEvaluationDataNumbers, TcbPolicy, TcbEvalNumber};
    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    use chrono::{Duration, TimeZone, Utc};

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn parse_sgx_tcb_evaluation_data_numbers() {
        let numbers = RawTcbEvaluationDataNumbers::<platform::SGX>::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certificates = [&root_certificate[..]];
        numbers.verify_ex(&root_certificates, &Utc.with_ymd_and_hms(2025, 6, 4, 12, 0, 0).unwrap()).unwrap();
    }

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn parse_tcb_evaluation_data_numbers_incorrect_signature() {
        let numbers = RawTcbEvaluationDataNumbers::<platform::SGX>::read_from_file("./tests/data").unwrap();
        let root_certificate = include_bytes!("../tests/data/root_SGX_CA_der.cert").to_owned();
        let root_certificates = [&root_certificate[..]];
        numbers.verify_ex(&root_certificates, &Utc.with_ymd_and_hms(2025, 6, 4, 12, 0, 0).unwrap()).unwrap();

        let mut corrupted = numbers.clone();
        corrupted.signature[10] = 0x66;
        if let Err(Error::UntrustworthyTcbEvaluationDataNumber(_s)) = corrupted.verify(&root_certificates) {
            ();
        } else {
            assert!(false);
        }
    }

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
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

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn minimum_tcb_evaluation_data_number() {
        let numbers = RawTcbEvaluationDataNumbers::<platform::SGX>::read_from_file("./tests/data").unwrap();
        let numbers: TcbEvaluationDataNumbers<platform::SGX, Unverified> = serde_json::from_str(numbers.raw_tcb_evaluation_data_numbers()).unwrap();

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

    #[cfg(not(target_env = "sgx"))]
    #[test]
    fn select_best() {
        use crate::pckcrt::{TcbComponents, SGXSpecificTcbComponentData};
        fn select(tcb_components: &TcbComponents<SGXSpecificTcbComponentData>, qesvn: u16) -> Result<u16, Error> {
            use std::convert::TryInto;
            TcbEvaluationDataNumbers::<platform::SGX, Unverified>::select_best("./tests/data/eval-num-select-best", &"00606a000000".try_into().unwrap(), tcb_components, qesvn)
                .map(|num| num.number)
        }
        // platform and QE are nonsensical: just choose highest
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([0; 16], 0), 0).unwrap(), 19);
        // platform is nonsensical: choose eval nums based on QE up-to-date
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([0; 16], 0), 8).unwrap(), 19);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([0; 16], 0), 6).unwrap(), 8);
        // QE is nonsensical: choose eval nums based on platform up-to-date
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([16, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 0).unwrap(), 19);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([15, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 0).unwrap(), 18);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([14, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 0).unwrap(), 17);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([7, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 0).unwrap(), 14);
        // platform and QE are fully up to date: choose highest
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([16, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 8).unwrap(), 19);
        // QE is up to date: choose up-to-date eval nums based on platform
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([15, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 8).unwrap(), 18);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([14, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 8).unwrap(), 17);
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([7, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 8).unwrap(), 8);
        // platform is up to date: choose up-to-date eval nums based on QE
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([16, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 6).unwrap(), 8);
        // neither platform and QE are up to date: choose highest eval nums where they were both up to date
        assert_eq!(select(&TcbComponents::<SGXSpecificTcbComponentData>::from_raw([4, 16, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 13), 5).unwrap(), 8);
    }
}
