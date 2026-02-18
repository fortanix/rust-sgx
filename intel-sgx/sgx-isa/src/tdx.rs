/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

//! Constants and structures related to the Intel TDX.

#[cfg(all(target_env = "sgx", not(feature = "sgxstd")))]
use crate::arch;
#[cfg(all(target_env = "sgx", feature = "sgxstd"))]
use std::os::fortanix_sgx::arch;

use core::fmt::Display;

use crate::{slice, struct_def};

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
    /// Ref: Intel® Trust Domain CPU Architectural Extensions, table 2-4.
    /// Version: 343754-002US, MAY 2021
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733582>
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
    /// Ref: Intel® Trust Domain CPU Architectural Extensions, table 2-5.
    /// Version: 343754-002US, MAY 2021
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733582>
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

#[cfg(target_env = "sgx")]
impl AsRef<tdx_arch::Align256<[u8; TdxReportMac::UNPADDED_SIZE]>> for TdxReportMac {
    fn as_ref(&self) -> &tdx_arch::Align256<[u8; Self::UNPADDED_SIZE]> {
        unsafe { &*(self as *const _ as *const _) }
    }
}

/// Size of a TDX report in bytes.
pub const TDX_REPORT_SIZE: usize = 1024;
pub const TEE_TCB_INFO_SIZE: usize = 239;
pub const TDX_REPORT_RESERVED_SIZE: usize = 17;
pub const TEE_INFO_SIZE: usize = 512;
pub const TDINFO_BASE_SIZE: usize = 448;
pub const TDINFO_EXTENSION_V1_SIZE: usize = 64;
pub const TDINFO_EXTENSION_V2_SIZE: usize = 320;
pub const TDINFO_V1_SIZE: usize = TDINFO_BASE_SIZE + TDINFO_EXTENSION_V1_SIZE;
pub const TDINFO_V2_SIZE: usize = TDINFO_BASE_SIZE + TDINFO_EXTENSION_V2_SIZE;
pub const TEE_TCB_INFO_VALID_SIZE: usize = 8;
pub const TEE_TCB_INFO_TEE_TCB_SVN_SIZE: usize = 16;
pub const TEE_TCB_INFO_MR_SIZE: usize = 48;
pub const TEE_TCB_INFO_ATTRIBUTES_SIZE: usize = 8;
pub const TEE_TCB_INFO_RESERVED_SIZE: usize = 111;

struct_def! {
    /// Rust definition of `TEE_TCB_INFO` from `TDREPORT_STRUCT`.
    ///
    /// Ref: Intel® Trust Domain CPU Architectural Extensions, Table 2-3
    /// Version: 343754-002US, MAY 2021
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733582>
    #[repr(C)]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TeeTcbInfo {
        /// (  0) Indicates TEE_TCB_INFO fields which are valid
        /// - 1 in the i-th significant bit reflects that the 8 bytes starting at
        /// offset (8 * i) are valid.
        /// -  0 in the i-th significant bit reflects that either 8 bytes starting at
        /// offset (8 * i) is not populated or reserved, and is set to zero.
        pub valid: [u8; TEE_TCB_INFO_VALID_SIZE],
        /// (  8) TEE_TCB_SVN array
        pub tee_tcb_svn: [u8; TEE_TCB_INFO_TEE_TCB_SVN_SIZE],
        /// ( 24) Measurement of the Intel TDX module
        pub mrseam: [u8; TEE_TCB_INFO_MR_SIZE],
        /// ( 72) Measurement of TDX module signer if valid
        pub mrsigner_seam: [u8; TEE_TCB_INFO_MR_SIZE],
        /// (120) Additional configuration ATTRIBUTES if valid
        pub attributes: [u8; TEE_TCB_INFO_ATTRIBUTES_SIZE],
        /// (128) Reserved, must be zero
        pub reserved: [u8; TEE_TCB_INFO_RESERVED_SIZE],
    }
}

impl TeeTcbInfo {
    pub const UNPADDED_SIZE: usize = TEE_TCB_INFO_SIZE;
}

struct_def! {
    /// Rust definition of `TDINFO_STRUCT` for REPORTTYPE.VERSION 0 or 1.
    ///
    /// Ref: Intel TDX Module Application Binary Interface (ABI) Reference, table 3.49.
    /// Version: Sep 2025, 348551-007US
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733579>
    #[repr(C, align(512))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TdInfoV1 {
        /// (  0) Base TDINFO fields
        pub base: [u8; TDINFO_BASE_SIZE],
        /// (448) Reserved extension for REPORTTYPE.VERSION 0 or 1
        pub extension: [u8; TDINFO_EXTENSION_V1_SIZE],
    }
}

impl TdInfoV1 {
    pub const UNPADDED_SIZE: usize = TDINFO_V1_SIZE;
}

struct_def! {
    /// Rust definition of `TDINFO_STRUCT` for REPORTTYPE.VERSION 2.
    ///
    /// Ref: Intel TDX Module Application Binary Interface (ABI) Reference, table 3.49.
    /// Version: Sep 2025, 348551-007US
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733579>
    #[repr(C)]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TdInfoV2 {
        /// (  0) Base TDINFO fields
        pub base: [u8; TDINFO_BASE_SIZE],
        /// (448) Extension for REPORTTYPE.VERSION 2
        pub extension: [u8; TDINFO_EXTENSION_V2_SIZE],
    }
}

impl TdInfoV2 {
    pub const UNPADDED_SIZE: usize = TDINFO_V2_SIZE;
}

struct_def! {
    /// Rust definition of `TDREPORT_STRUCT` from the output of the `TDG.MR.REPORT` function.
    /// Total size of this variant is __1024__ bytes with `report_mac.report_type.version` equals __0 or 1__.
    ///
    /// Note: `TDG.MR.REPORT` is one variant of syscall `TDCALL`.
    ///
    /// Ref: Intel TDX Module Application Binary Interface (ABI) Reference, table 3.45.
    /// Version: Sep 2025, 348551-007US
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733579>
    #[repr(C, align(1024))]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TdxReportV1 {
        /// (  0) Report mac struct for SGX report type 2
        pub report_mac: TdxReportMac,
        /// (256) Struct contains details about extra TCB elements not found in CPUSVN
        pub tee_tcb_info: TeeTcbInfo,
        /// (495) Reserved, must be zero
        pub reserved: [u8; TDX_REPORT_RESERVED_SIZE],
        /// (512) Structure containing the TD’s attestable properties.
        pub td_info: TdInfoV1,
    }
}

impl TdxReportV1 {
    pub const UNPADDED_SIZE: usize = 1024;

    #[cfg(target_env = "sgx")]
    pub fn verify(&self) -> Result<(), TdxAttestErrorCode> {
        Ok(tdx_arch::everifyreport2(self.report_mac.as_ref())?)
    }
}

struct_def! {
    /// Rust definition of `TDREPORT_STRUCT` from the output of the `TDG.MR.REPORT` function.
    /// Total size of this variant is __1280__ bytes with `report_mac.report_type.version` equals __2__.
    ///
    /// Note: `TDG.MR.REPORT` is one variant of syscall `TDCALL`.
    ///
    /// Ref: Intel TDX Module Application Binary Interface (ABI) Reference, table 3.45.
    /// Version: Sep 2025, 348551-007US
    /// Link: <https://cdrdv2.intel.com/v1/dl/getContent/733579>
    #[repr(C)]
    #[cfg_attr(
        feature = "large_array_derive",
        derive(Clone, Debug, Eq, PartialEq)
    )]
    pub struct TdxReportV2 {
        /// (  0) Report mac struct for SGX report type 2
        pub report_mac: TdxReportMac,
        /// (256) Struct contains details about extra TCB elements not found in CPUSVN
        pub tee_tcb_info: TeeTcbInfo,
        /// (495) Reserved, must be zero
        pub reserved: [u8; TDX_REPORT_RESERVED_SIZE],
        /// (512) Structure containing the TD’s attestable properties.
        pub td_info: TdInfoV2,
    }
}

impl TdxReportV2 {
    pub const UNPADDED_SIZE: usize = 1280;

    #[cfg(target_env = "sgx")]
    pub fn verify(&self) -> Result<(), TdxAttestErrorCode> {
        Ok(tdx_arch::everifyreport2(self.report_mac.as_ref())?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TdxReport {
    V1(TdxReportV1),
    V2(TdxReportV2),
}

impl AsRef<[u8]> for TdxReport {
    fn as_ref(&self) -> &[u8] {
        match self {
            TdxReport::V1(tdx_report_v1) => tdx_report_v1.as_ref(),
            TdxReport::V2(tdx_report_v2) => tdx_report_v2.as_ref(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdxError {
    /// Given bytes is not supported, currently only 1024 and 1280 is supported.
    UnsupportedSize,
    /// The report's `report_mac.report_type.version` number is inconsistent with its size.
    InconsistentReportVersion,
    /// TDX attestation error
    ErrorCode(TdxAttestErrorCode),
}

impl Display for TdxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TdxError::UnsupportedSize => f.write_str("Unsupported size of bytes for a TDX report"),
            TdxError::InconsistentReportVersion => {
                f.write_str("TDX report size does not match its version number")
            }
            TdxError::ErrorCode(err) => write!(f, "TdxAttestErrorCode: {}", err),
        }
    }
}

#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
impl std::error::Error for TdxError {}

impl TdxReport {
    pub fn try_copy_from(src: &[u8]) -> Result<Self, TdxError> {
        match src.len() {
            TdxReportV1::UNPADDED_SIZE => {
                let report = TdxReportV1::try_copy_from(src).expect("verified");
                match report.report_mac.report_type.version {
                    0 | 1 => Ok(Self::V1(report)),
                    _ => Err(TdxError::InconsistentReportVersion),
                }
            }
            TdxReportV2::UNPADDED_SIZE => {
                let report = TdxReportV2::try_copy_from(src).expect("verified");
                match report.report_mac.report_type.version {
                    2 => Ok(Self::V2(report)),
                    _ => Err(TdxError::InconsistentReportVersion),
                }
            }
            _ => Err(TdxError::UnsupportedSize),
        }
    }

    #[cfg(target_env = "sgx")]
    pub fn verify(&self) -> Result<(), TdxAttestErrorCode> {
        match self {
            TdxReport::V1(tdx_report_v1) => tdx_report_v1.verify(),
            TdxReport::V2(tdx_report_v2) => tdx_report_v2.verify(),
        }
    }
}

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

#[cfg(not(feature = "large_array_derive"))]
mod debug_impl {
    use super::*;
    use core::fmt::{Debug, Formatter, Result};

    impl Debug for TdxReportMac {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TdxReportMac")
                .field("report_type", &self.report_type)
                .field("reserved1", &self.reserved1)
                .field("cpu_svn", &self.cpu_svn)
                .field("tee_tcb_info_hash", &self.tee_tcb_info_hash)
                .field("tee_info_hash", &self.tee_info_hash)
                .field("report_data", &self.report_data)
                .field("reserved2", &self.reserved2)
                .field("mac", &self.mac)
                .finish()
        }
    }

    impl Debug for TdxReportV1 {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TdxReport")
                .field("report_mac", &self.report_mac)
                .field("tee_tcb_info", &self.tee_tcb_info)
                .field("reserved", &self.reserved)
                .field("tee_info", &self.td_info)
                .finish()
        }
    }

    impl Debug for TdxReportV2 {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TdxReport")
                .field("report_mac", &self.report_mac)
                .field("tee_tcb_info", &self.tee_tcb_info)
                .field("reserved", &self.reserved)
                .field("tee_info", &self.td_info)
                .finish()
        }
    }

    impl Debug for TeeTcbInfo {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TeeTcbInfo")
                .field("valid", &self.valid)
                .field("tee_tcb_svn", &self.tee_tcb_svn)
                .field("mrseam", &self.mrseam)
                .field("mrsigner_seam", &self.mrsigner_seam)
                .field("attributes", &self.attributes)
                .field("reserved", &self.reserved)
                .finish()
        }
    }

    impl Debug for TdInfoV1 {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TdInfoV1")
                .field("base", &self.base)
                .field("extension", &self.extension)
                .finish()
        }
    }

    impl Debug for TdInfoV2 {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("TdInfoV1")
                .field("base", &self.base)
                .field("extension", &self.extension)
                .finish()
        }
    }
}

/// Since this is not upstreamed to rust yet.
#[cfg(target_env = "sgx")]
mod tdx_arch {
    use crate::Enclu;
    use core::arch::asm;

    /// Wrapper struct to force 256-byte alignment.
    #[repr(align(256))]
    pub struct Align256<T>(pub T);

    /// Call the `EVERIFYREPORT2` instruction to verify a 256-bit TDX REPORT MAC struct.
    /// The concrete type is [`crate::tdx::TdxReportMac`].
    pub fn everifyreport2(tdx_report_mac: &Align256<[u8; 256]>) -> Result<(), u32> {
        unsafe {
            let error: u32;
            asm!(
                "xchg %rbx, {0}",
                "enclu",
                "mov {0}, %rbx",
                "jz 1f",
                "xor %eax, %eax",
                "1:",
                inout(reg) tdx_report_mac => _,
                inlateout("eax") Enclu::EVerifyReport2 as u32 => error,
                options(att_syntax, nostack),
            );
            match error {
                0 => Ok(()),
                err => Err(err),
            }
        }
    }
}
