/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

//! Constants and structures related to the Intel TDX.

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
}
