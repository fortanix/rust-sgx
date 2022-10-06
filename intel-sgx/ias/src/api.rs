/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use sgx_isa::{Attributes, Miscselect, Report};
use std::str;
use std::fmt;
use byteorder::{BigEndian, ReadBytesExt};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum IasVersion {
    V2 = 2,
    V3,
    V4
}

pub const LATEST_IAS_VERSION: IasVersion = IasVersion::V4;

/// Adapts `serde_bytes` for `Option<T: AsRef<[u8]>>` and `Option<T: From<Vec<u8>>>`
mod serde_option_bytes {
    use serde_bytes;
    use serde::de::{Deserializer, Visitor};
    use serde::ser::Serializer;
    use std::marker::PhantomData;

    pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where T: serde_bytes::Serialize,
              S: Serializer
    {
        match *value {
            Some(ref bytes) => serde_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> ::std::result::Result<Option<T>, D::Error>
        where D: Deserializer<'de>,
              T: serde_bytes::Deserialize<'de>
    {
        struct VisitorImpl<'de, T: serde_bytes::Deserialize<'de>>(PhantomData<&'de ()>, PhantomData<T>);
        impl<'de, T> Visitor<'de> for VisitorImpl<'de, T>
            where T: serde_bytes::Deserialize<'de>
        {
            type Value = Option<T>;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "an optional byte array")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
                Ok(Some(serde_bytes::deserialize(deserializer)?))
            }
        }
        deserializer.deserialize_option(VisitorImpl(PhantomData, PhantomData))
    }
}

/// A request body for the IAS "verify attestation evidence" endpoint.  Refer to
/// the IAS API Specification.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyAttestationEvidenceRequest {
    #[serde(with = "serde_bytes")]
    pub isv_enclave_quote: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none", with = "self::serde_option_bytes")]
    pub pse_manifest: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>, // IAS spec: max length 32 characters
}

/// The ISV enclave quote body as returned in VerifyAttestationEvidenceResponse.
/// Compared to sgx_isa::Report, this has some QE metadata at the front, and
/// omits keyid and mac at the end. Everything else is the same.
/// Refer to the IAS API Specification.
#[repr(C)]
pub struct EnclaveQuoteBody {
    // "BODY" in the IAS API spec
    pub version:    u16,
    pub signature_type: u16,
    pub gid:        [u8; 4],
    pub isvsvn_qe:  u16,
    pub isvsvn_pce: u16,
    pub _reserved0: [u8;  4],
    pub basename:   [u8; 32],

    // "REPORTDATA" in the IAS API spec
    pub cpusvn:     [u8; 16],
    pub miscselect: Miscselect,
    pub _reserved1: [u8; 28],
    pub attributes: Attributes,
    pub mrenclave:  [u8; 32],
    pub _reserved2: [u8; 32],
    pub mrsigner:   [u8; 32],
    pub _reserved3: [u8; 96],
    pub isvprodid:  u16,
    pub isvsvn:     u16,
    pub _reserved4: [u8; 60],
    pub reportdata: [u8; 64],
}

pub const ENCLAVE_QUOTE_BODY_LEN: usize = 432;

impl EnclaveQuoteBody {
    /// If `src` has the correct length, returns `Some<EnclaveQuoteBody>`
    /// copied from `src`, else returns `None`.
    pub fn try_copy_from(src: &[u8]) -> Option<Self> {
        if src.len() == ENCLAVE_QUOTE_BODY_LEN {
            unsafe {
                Some(::std::ptr::read_unaligned(src.as_ptr() as *const EnclaveQuoteBody))
            }
        } else {
            None
        }
    }

    // Compile time check that the size argument is correct.
    // Not otherwise used.
    unsafe fn _check_size(b: Self) -> [u8; ENCLAVE_QUOTE_BODY_LEN] {
        ::std::mem::transmute(b)
    }

    // Report of the Enclave being attested.
    // key_id and mac are required parameter hence have to pass default value for them
    // as these values are not present in EnclaveQuoteBody
    pub fn get_report(self) -> Report {
        let EnclaveQuoteBody{cpusvn, miscselect, _reserved1, attributes, mrenclave, _reserved2, mrsigner, _reserved3, isvprodid, isvsvn, _reserved4, reportdata, ..} = self;
        Report {
            cpusvn,
            miscselect,
            _reserved1,
            attributes,
            mrenclave,
            _reserved2,
            mrsigner,
            _reserved3,
            isvprodid,
            isvsvn,
            _reserved4,
            reportdata,
            keyid: [0; 32],
            mac: [0; 16],
        }
    }
}

fn two() -> u64 {
    2
}

fn less_than_three(&v: &u64) -> bool {
    v < 3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IasAdvisoryId(pub String);

impl From<String> for IasAdvisoryId {
    fn from(s: String) -> Self {
        IasAdvisoryId(s)
    }
}

impl std::cmp::PartialEq for IasAdvisoryId {
    fn eq(&self, other: &Self) -> bool {
        let IasAdvisoryId(s) = self;
        let IasAdvisoryId(o) = other;

        s.to_uppercase() == o.to_uppercase()
    }

    fn ne(&self, other: &IasAdvisoryId) -> bool {
        !self.eq(other)
    }
}

impl std::cmp::Eq for IasAdvisoryId {}

/// A response body for the IAS "verify attestation evidence" endpoint.  Refer
/// to the IAS API Specification.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyAttestationEvidenceResponse {
    pub id: String, // TODO: decimal big integer

    pub timestamp: String, // TODO: DateTime<UTC>, but DateTime serde doesn't
                           // like the IAS timestamp format.

    #[serde(default = "two", skip_serializing_if = "less_than_three")]
    pub version: u64,

    pub isv_enclave_quote_status: QuoteStatus,

    #[serde(with = "serde_bytes")]
    pub isv_enclave_quote_body: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<u32>, // TODO: enum RFC5280 CRLReason

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pse_manifest_status: Option<String>, // TODO: enum per IAS spec

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pse_manifest_hash: Option<String>, // TODO: base16 blob

    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_info_blob: Option<String>, // TODO: base16 blob

    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", with = "self::serde_option_bytes")]
    pub epid_pseudonym: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "advisoryURL")]
    pub advisory_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "advisoryIDs")]
    pub advisory_ids: Option<Vec<IasAdvisoryId>>,
}

/// Attestation verification status enum. Refer to "Attestation Verification
/// Report" in the IAS API specification.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuoteStatus {
    Ok,
    SignatureInvalid,
    GroupRevoked,
    SignatureRevoked,
    KeyRevoked,
    SigRlVersionMismatch,
    GroupOutOfDate,
    ConfigurationNeeded,
    SwHardeningNeeded,
    ConfigurationAndSwHardeningNeeded,
}

macro_rules! pif_v2_bitflags {
    ($($k:ident = $v:expr);* $(;)*) => (
        bitflags! {
            pub struct PlatformInfoFlagsV2: u64 {
                $(const $k = $v;)*
            }
        }

        static PIF_V2_NAMES: &'static [(PlatformInfoFlagsV2, &'static str)] = &[
            $((PlatformInfoFlagsV2::$k, stringify!($k)),)*
        ];
    )
}

pif_v2_bitflags! {
    // See Intel Linux SGX PSW, psw/ae/aesm_service/source/common/platform_info_blob.h
    /* Masks for sgx_epid_group_flags */
    QE_EPID_GROUP_REVOKED                           = 0x01_0000_0000;
    PERF_REKEY_FOR_QE_EPID_GROUP_AVAILABLE          = 0x02_0000_0000;
    QE_EPID_GROUP_OUT_OF_DATE                       = 0x04_0000_0000;

    /* Masks for sgx_tcb_evaluation_flags */
    QUOTE_CPUSVN_OUT_OF_DATE                        = 0x00_0001_0000;
    QUOTE_ISVSVN_QE_OUT_OF_DATE                     = 0x00_0002_0000;
    QUOTE_ISVSVN_PCE_OUT_OF_DATE                    = 0x00_0004_0000;
    PLATFORM_CONFIGURATION_NEEDED                   = 0x00_0008_0000;

    /* Masks for sgx_pse_evaluation_flags PS_SEC_PROP_DESC.PSE_ISVSVN is out of date */
    PSE_ISVSVN_OUT_OF_DATE                          = 0x00_0000_0001;
    EPID_GROUP_ID_BY_PS_HW_GID_REVOKED              = 0x00_0000_0002;
    SVN_FROM_PS_HW_SEC_INFO_OUT_OF_DATE             = 0x00_0000_0004;
    SIGRL_VER_FROM_PS_HW_SIG_RLVER_OUT_OF_DATE      = 0x00_0000_0008;
    PRIVRL_VER_FROM_PS_HW_PRV_KEY_RLVER_OUT_OF_DATE = 0x00_0000_0010;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PlatformStatus {
    V2(PlatformInfoFlagsV2)
}

impl fmt::Display for PlatformStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let &PlatformStatus::V2(mut flags) = self;
        for &(val, name) in PIF_V2_NAMES {
            if flags.contains(val) {
                flags.remove(val);
                write!(f, "{}", name)?;
                if !flags.is_empty() {
                    write!(f, ", ")?;
                }
            }
        }
        Ok(())
    }
}

impl str::FromStr for PlatformStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        fn parse_hex(s: &str) -> Option<Vec<u8>> {
            if !s.is_ascii() || (s.len() % 2) == 1 {
                return None
            }
            s.as_bytes().chunks(2).map(|v| u8::from_str_radix(str::from_utf8(v).unwrap(/*is_ascii*/), 16).ok() ).collect()
        }

        const PLATFORM_INFO_BLOB_TYPE: u8 = 21;
        const PLATFORM_INFO_BLOB_VERSION: u8 = 2;
        const PLATFORM_INFO_BLOB_V2_LEN: u16 = 101;

        let pinfo = parse_hex(s).ok_or_else(|| warn!("Platform info blob is not properly hex encoded") )?;
        let pinfo = &mut &pinfo[..];

        let type_ = pinfo.read_u8().map_err(|_|())?;
        let version = pinfo.read_u8().map_err(|_|())?;
        let len = pinfo.read_u16::<BigEndian>().map_err(|_|())?;
        if (type_, version, len) != (PLATFORM_INFO_BLOB_TYPE, PLATFORM_INFO_BLOB_VERSION, PLATFORM_INFO_BLOB_V2_LEN) {
            warn!("Platform info blob TLV mismatch");
            return Err(())
        }

        let status = pinfo.read_uint::<BigEndian>(5).map_err(|_|())?;
        if let Some(bits) = PlatformInfoFlagsV2::from_bits(status) {
            Ok(PlatformStatus::V2(bits))
        } else {
            warn!("Platform info blob unexpected status bits set: {:010x}", status);
            Err(())
        }
    }
}

#[test]
fn parse_platform_info_blob() {
    let blob = "1502006504000100000707020401010000000000000000000005000004000000020000000000000AC888E762232B197B0114CFBFF28163B0D5EF1501399EFE6FF0A7F0CAD93E3A50AD744BA39C8A44FB91F17F5806687202BE0AE5459CD5613588A7B7539E003ABD48";
    assert_eq!(blob.parse::<PlatformStatus>().unwrap(), PlatformStatus::V2(PlatformInfoFlagsV2::QE_EPID_GROUP_OUT_OF_DATE | PlatformInfoFlagsV2::QUOTE_CPUSVN_OUT_OF_DATE));
}
