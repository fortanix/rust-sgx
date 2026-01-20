//! Safe(er) Rust wrappers for the TDX attestation APIs.
//!
//! This module exposes higher-level types around the raw TDX attestation
//! interfaces and mirrors the semantics described in the upstream TDX
//! attestation headers.

#[macro_use]
extern crate memory_layout;

use memory_layout::impl_default_clone_eq;
use std::slice;
use tdx_module::tdx_rtmr_event_t;

pub mod tdx_attest;

use tdx_attest::{TdxAttestError, tdx_report_data_t, tdx_report_t};

/// SHA384
pub const TEE_HASH_384_SIZE: usize = 48;
/// Message SHA 256 HASH Code - 32 bytes
pub const TEE_MAC_SIZE: usize = 32;

pub const TDX_REPORT_DATA_SIZE: usize = 64;
pub const TEE_CPU_SVN_SIZE: usize = 16;

/// SGX Legacy Report Type
pub const SGX_LEGACY_REPORT_TYPE: usize = 0x0;
/// TEE Report Type2
pub const TEE_REPORT2_TYPE: usize = 0x8;
/// SUBTYPE for Report Type2 is 0
pub const TEE_REPORT2_SUBTYPE: usize = 0x0;
/// VERSION for Report Type2 is 0
pub const TEE_REPORT2_VERSION: usize = 0x0;
/// VERSION for Report Type2 which mr_servicetd is used
pub const TEE_REPORT2_VERSION_SERVICETD: usize = 0x1;

// Ref: https://github.com/intel/confidential-computing.sgx/blob/main/common/inc/sgx_report2.h
struct_def! {
    #[repr(C, align(4))]
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct TeeReportType {
        /// Trusted Execution Environment(TEE) type:
        ///   0x00:      SGX Legacy REPORT TYPE
        ///   0x7F-0x01: Reserved
        ///   0x80:      Reserved
        ///   0x81:      TEE Report type 2
        ///   0xFF-0x82: Reserved
        pub report_type: u8,
        /// TYPE-specific subtype, Stage1: value is 0
        pub subtype: u8,
        /// TYPE-specific version, Stage1: value is 0
        pub version: u8,
        pub reserved: u8,
    }
}

impl TeeReportType {
    pub const UNPADDED_SIZE: usize = 4;
}


pub const TDX_REPORT_MAC_STRUCT_SIZE: usize = 256;
pub const TDX_REPORT_MAC_STRUCT_RESERVED1_BYTES: usize = 12;
pub const TDX_REPORT_MAC_STRUCT_RESERVED2_BYTES: usize = 32;

// Ref: https://github.com/intel/confidential-computing.sgx/blob/main/common/inc/sgx_report2.h
struct_def! {
    #[repr(C, align(256))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Default, Eq, PartialEq)
    )]
    pub struct TdxReportMac {
        /// (  0) TEE Report type
        pub report_type: TeeReportType,
        /// (  4) Reserved, must be zero
        pub reserved1: [u8; TDX_REPORT_MAC_STRUCT_RESERVED1_BYTES],
        /// ( 16) Security Version of the CPU
        pub cpu_svn: [u8; TEE_CPU_SVN_SIZE],
        /// ( 32) SHA384 of TEE_TCB_INFO for TEEs
        pub tee_tcb_info_hash:[u8; TEE_HASH_384_SIZE],
        /// ( 80) SHA384 of TEE_INFO
        pub tee_info_hash: [u8; TEE_HASH_384_SIZE],
        /// (128) Data provided by the user
        pub report_data: [u8; TDX_REPORT_DATA_SIZE],
        /// (192) Reserved, must be zero
        pub reserved2: [u8; TDX_REPORT_MAC_STRUCT_RESERVED2_BYTES],
        /// (224) The Message Authentication Code over this structure
        pub mac: [u8; TEE_MAC_SIZE],
    }
}

impl TdxReportMac {
    pub const UNPADDED_SIZE: usize = 256;
}

/// Size of a TDX report in bytes.
pub const TDX_REPORT_SIZE: usize = 1024;
pub const TEE_TCB_INFO_SIZE: usize = 239;
pub const TDX_REPORT_RESERVED_SIZE: usize = 17;
pub const TEE_INFO_SIZE: usize = 512;

// Ref: https://github.com/intel/confidential-computing.sgx/blob/main/common/inc/sgx_report2.h
struct_def! {
    #[repr(C, align(1024))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Default, Eq, PartialEq)
    )]
    pub struct TdxReport {
        /// (  0) Report mac struct for SGX report type 2
        pub report_mac: TdxReportMac,
        /// (256) Struct contains details about extra TCB elements not found in CPUSVN
        pub tee_tcb_info: [u8; TEE_TCB_INFO_SIZE],
        /// (495) Reserved, must be zero
        pub reserved: [u8; TDX_REPORT_RESERVED_SIZE],
        /// (512) Struct contains the TEE Info
        pub tee_info: [u8; TEE_INFO_SIZE],
    }
}

impl From<tdx_report_t> for TdxReport {
    fn from(report: tdx_report_t) -> Self {
        Self::try_copy_from(&report.d).expect("validated size")
    }
}

impl From<TdxReport> for tdx_report_t {
    fn from(report: TdxReport) -> Self {
        let mut d = [0u8; TDX_REPORT_SIZE];
        d.copy_from_slice(report.as_ref());
        tdx_report_t { d }
    }
}

impl TdxReport {
    pub const UNPADDED_SIZE: usize = 1024;

    /// Request a TDX Report of the calling TD.
    ///
    /// The caller provides data intended to be cryptographically bound to the
    /// resulting report. This data does not need confidentiality protection.
    ///
    /// # Parameters
    /// - **report_data**: Data to cryptographically bind to the report, typically
    ///   a hash. It may be all zeros.
    ///
    /// # Errors
    /// Propagates the underlying TDX attestation error code.
    pub fn get_report(report_data: [u8; TDX_REPORT_DATA_SIZE]) -> Result<Self, TdxAttestError> {
        let mut tdx_report = tdx_report_t {
            d: [0; TDX_REPORT_SIZE],
        };
        let report_data = tdx_report_data_t { d: report_data };
        tdx_attest::parse_tdx_attest_error(tdx_attest::tdx_att_get_report(
            Some(&report_data),
            &mut tdx_report,
        ))?;
        Ok(tdx_report.into())
    }
}

pub const TDX_RTMR_EVENT_HEADER_SIZE: usize = 68;
/// Size of the RTMR extend data field in bytes.
pub const TDX_RTMR_EXTEND_DATA_SIZE: usize = 48;

#[repr(u8)]
pub enum TdxStatus {
    Success = 0,
    InvalidParameter = 1,
    AccessDenied = 2,
    InternalError = 255,
}

pub const REMR_EXTEND_DATA_SIZE: usize = 48;

/// Extend one of the TDX runtime measurement registers (RTMRs).
///
/// RTMR[rtmr_index] = SHA384(RTMR[rtmr_index] || extend_data)
/// - `rtmr_index`: only supported RTMR index is 2 and 3.
/// - `event_data`: field is currently expected to be empty by the platform
///   quoting infrastructure.
/// - `rtmr_index` and `extend_data` are fields in the structure that is an input of
///   this API.
///
/// ## Notes
///
/// This API does not return either the new or old value of the specified RTMR.
/// The [`TdxReport::get_report`] API may be used for this.
/// The input to this API includes a description of the “extend data”. This is
/// intended to facilitate reconstruction of the RTMR value. This, in turn,
/// suggests maintenance of an event log by the callee. Currently, event_data is
/// not supported.
pub fn extend_rtmr(
    rtmr_index: u64,
    extend_data: [u8; REMR_EXTEND_DATA_SIZE],
) -> Result<(), TdxAttestError> {
    match rtmr_index {
        2..=3 => (),
        _ => return Err(TdxAttestError::InvalidRtmrIndex),
    };
    // From: `tdx_attest_sys` crate generated binding code
    // ```C
    // typedef struct _tdx_rtmr_event_t {
    //     uint32_t	version;
    //     uint64_t 	rtmr_index;
    //     uint8_t 	extend_data[48];
    //     uint32_t 	event_type;
    //     uint32_t 	event_data_size;
    //     uint8_t 	event_data[];
    // } tdx_rtmr_event_t;
    // ```
    let mut rtmr_event = [0u8; std::mem::size_of::<tdx_rtmr_event_t>()];
    rtmr_event[0..0 + 4].copy_from_slice(&1u32.to_ne_bytes());
    rtmr_event[4..4 + 8].copy_from_slice(&rtmr_index.to_ne_bytes());
    rtmr_event[12..12 + REMR_EXTEND_DATA_SIZE].copy_from_slice(&extend_data);

    tdx_attest::parse_tdx_attest_error(tdx_attest::tdx_att_extend(&rtmr_event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdx_att_get_report() {
        let result = TdxReport::get_report([0; TDX_REPORT_DATA_SIZE]);
        assert!(matches!(result, Err(TdxAttestError::DeviceFailure)));
    }

    #[test]
    fn test_tdx_att_extend() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;
        let result = extend_rtmr(2, extend_data);
        assert!(matches!(result, Err(TdxAttestError::DeviceFailure)));
        let result = extend_rtmr(77, extend_data);
        assert!(matches!(result, Err(TdxAttestError::InvalidRtmrIndex)));
    }
}
