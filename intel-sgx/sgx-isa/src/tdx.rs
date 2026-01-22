/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

//! Constants and structures related to the Intel TDX.

use core::fmt::Display;

use crate::slice;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdxAttestErrorCode {
    Success,
    Unexpected(u32),
    InvalidParameter,
    OutOfMemory,
    VsockFailure,
    ReportFailure,
    ExtendFailure,
    NotSupported,
    QuoteFailure,
    Busy,
    DeviceFailure,
    InvalidRtmrIndex,
    UnsupportedAttKeyId,
}

#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
impl std::error::Error for TdxAttestErrorCode {}

impl From<u32> for TdxAttestErrorCode {
    fn from(v: u32) -> Self {
        match v {
            0x0000 => Self::Success,
            0x0002 => Self::InvalidParameter,
            0x0003 => Self::OutOfMemory,
            0x0004 => Self::VsockFailure,
            0x0005 => Self::ReportFailure,
            0x0006 => Self::ExtendFailure,
            0x0007 => Self::NotSupported,
            0x0008 => Self::QuoteFailure,
            0x0009 => Self::Busy,
            0x000a => Self::DeviceFailure,
            0x000b => Self::InvalidRtmrIndex,
            0x000c => Self::UnsupportedAttKeyId,
            num => Self::Unexpected(num),
        }
    }
}

impl Display for TdxAttestErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TdxAttestErrorCode::Success => f.write_str("Success"),
            TdxAttestErrorCode::Unexpected(num) => f.write_fmt(format_args!("Unexoected error code: {}", num)),
            TdxAttestErrorCode::InvalidParameter => f.write_str("The parameter is incorrect"),
            TdxAttestErrorCode::OutOfMemory => f.write_str("Not enough memory is available to complete this operation"),
            TdxAttestErrorCode::VsockFailure => f.write_str("vsock related failure"),
            TdxAttestErrorCode::ReportFailure => f.write_str("Failed to get the TD Report"),
            TdxAttestErrorCode::ExtendFailure => f.write_str("Failed to extend rtmr"),
            TdxAttestErrorCode::NotSupported => f.write_str("Request feature is not supported"),
            TdxAttestErrorCode::QuoteFailure => f.write_str("Failed to get the TD Quote"),
            TdxAttestErrorCode::Busy => f.write_str("The device driver return busy"),
            TdxAttestErrorCode::DeviceFailure => f.write_str("Failed to acess tdx attest device"),
            TdxAttestErrorCode::InvalidRtmrIndex => f.write_str("Only supported RTMR index is 2 and 3"),
            TdxAttestErrorCode::UnsupportedAttKeyId => f.write_str("The platform Quoting infrastructure does not support any of the keys described in att_key_id_list"),
        }
    }
}

}
