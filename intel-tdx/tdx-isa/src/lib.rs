//! Safe(er) Rust wrappers for the TDX attestation APIs.
//!
//! This module exposes higher-level types around the raw TDX attestation
//! interfaces and mirrors the semantics described in the upstream TDX
//! attestation headers.

#[macro_use]
extern crate memory_layout;

use memory_layout::impl_default_clone_eq;
use std::slice;
use thiserror::Error;

#[cfg(feature = "tdx-module")]
pub mod tdx_attest;
#[cfg(feature = "ioctl")]
pub mod tdx_ioctl;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TdxAttestError {
    /// Lower bound for error translations.
    #[error("Indicate min error to allow better translation, should be unexpected in production")]
    Min,
    #[error("The parameter is incorrect")]
    InvalidParameter,
    #[error("Not enough memory is available to complete this operation")]
    OutOfMemory,
    #[error("vsock related failure")]
    VsockFailure,
    #[error("Failed to get the TD Report")]
    ReportFailure,
    #[error("Failed to extend rtmr")]
    ExtendFailure,
    #[error("Request feature is not supported")]
    NotSupported,
    #[error("Failed to get the TD Quote")]
    QuoteFailure,
    #[error("The device driver return busy")]
    Busy,
    #[error("Failed to acess tdx attest device")]
    DeviceFailure,
    #[error("Only supported RTMR index is 2 and 3")]
    InvalidRtmrIndex,
    #[error(
        "The platform Quoting infrastructure does not support any of the keys described in att_key_id_list"
    )]
    UnsupportedAttKeyId,
    /// Upper bound for error translations.
    #[error("Indicate max error to allow better translation, should be unexpected in production")]
    Max,
}

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

struct_def! {
    /// Rust definition of `REPORTTYPE` from `REPORTMACSTRUCT`.
    ///
    /// Ref: Intel TDX Module ABI Specification, section 4.7.4.
    /// Link to latest version (Sep 2025): https://cdrdv2.intel.com/v1/dl/getContent/733579
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

struct_def! {
    /// Rust definition of `REPORTMACSTRUCT` from `TDREPORT_STRUCT`.
    ///
    /// Ref: Intel TDX Module ABI Specification, section 4.7.3.
    /// Link to latest version (Sep 2025): https://cdrdv2.intel.com/v1/dl/getContent/733579
    #[repr(C, align(256))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TdxReportMac {
        /// (  0) TEE Report type
        pub report_type: TeeReportType,
        /// (  4) Reserved, must be zero
        pub reserved1: [u8; TDX_REPORT_MAC_STRUCT_RESERVED1_BYTES],
        /// ( 16) Security Version of the CPU
        pub cpu_svn: [u8; TEE_CPU_SVN_SIZE],
        /// ( 32) SHA384 of TEE_TCB_INFO for TEEs
        pub tee_tcb_info_hash: [u8; TEE_HASH_384_SIZE],
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

struct_def! {
    /// Rust definition of `TDREPORT_STRUCT` from the output of the `TDG.MR.REPORT` function.
    /// `TDG.MR.REPORT` is one variant of syscall `TDCALL`.
    ///
    /// Ref: Intel TDX Module ABI Specification, section 4.7.2.
    /// Link to latest version (Sep 2025): https://cdrdv2.intel.com/v1/dl/getContent/733579
    #[repr(C, align(1024))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
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
        #[cfg(feature = "ioctl")]
        {
            return tdx_ioctl::get_report(report_data);
        }
        #[cfg(all(not(feature = "ioctl"), feature = "tdx-module"))]
        {
            return tdx_attest::get_report(report_data);
        }
        #[cfg(not(any(feature = "ioctl", feature = "tdx-module")))]
        {
            Err(TdxAttestError::NotSupported)
        }
    }
}

pub const TDX_RTMR_EVENT_HEADER_SIZE: usize = 68;
/// Size of the RTMR extend data field in bytes.
pub const TDX_RTMR_EXTEND_DATA_SIZE: usize = 48;

/// Extend one of the TDX runtime measurement registers (RTMRs).
///
/// `RTMR[rtmr_index] = SHA384(RTMR[rtmr_index] || extend_data)`
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
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_SIZE],
) -> Result<(), TdxAttestError> {
    #[cfg(feature = "ioctl")]
    {
        return tdx_ioctl::extend_rtmr(rtmr_index, extend_data);
    }
    #[cfg(all(not(feature = "ioctl"), feature = "tdx-module"))]
    {
        return tdx_attest::extend_rtmr(rtmr_index, extend_data);
    }
    #[cfg(not(any(feature = "ioctl", feature = "tdx-module")))]
    {
        Err(TdxAttestError::NotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdx_att_get_report_invalid_device() {
        let expected_err = if cfg!(any(feature = "ioctl", feature = "tdx-module")) {
            TdxAttestError::DeviceFailure
        } else {
            TdxAttestError::NotSupported
        };
        let result = TdxReport::get_report([0; TDX_REPORT_DATA_SIZE]);
        match result {
            Ok(_) => panic!("expecting error"),
            Err(err) => assert_eq!(err, expected_err),
        }
    }

    #[test]
    fn test_tdx_att_extend_invalid_device() {
        let expected_err = if cfg!(any(feature = "ioctl", feature = "tdx-module")) {
            TdxAttestError::DeviceFailure
        } else {
            TdxAttestError::NotSupported
        };

        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;
        let err = extend_rtmr(2, extend_data).expect_err("expecting err");
        assert_eq!(err, expected_err);
    }

    #[test]
    fn test_tdx_att_extend_invalid_index() {
        let expected_err = if cfg!(any(feature = "ioctl", feature = "tdx-module")) {
            TdxAttestError::InvalidRtmrIndex
        } else {
            TdxAttestError::NotSupported
        };

        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;

        let err = extend_rtmr(77, extend_data).expect_err("expecting err");
        assert_eq!(err, expected_err);
    }
}
