/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

#![doc = include_str!("../README.md")]

use nix::errno::Errno;
pub use sgx_isa::REPORT_DATA_SIZE;
pub use sgx_isa::tdx::{TdxReportV1, TDX_REPORT_SIZE};

pub mod tdx_ioctl;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TdxError {
    Success,
    BadAddress,
    Busy,
    DeviceFailure,
    ExtendFailure,
    Interrupted,
    InvalidCpuSvn,
    InvalidParameter,
    InvalidReportMacStruct,
    InvalidRtmrIndex,
    NotSupported,
    OutOfMemory,
    QuoteFailure,
    ReportFailure,
    TdcallFailure,
    UnsupportedAttKeyId,
    VsockFailure,
    WrongDevice,
    Unexpected(u32),
}

impl core::fmt::Display for TdxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TdxError::Success => f.write_str("Success"),
            TdxError::BadAddress => f.write_str("Bad address"),
            TdxError::Busy => f.write_str("The device driver return busy"),
            TdxError::DeviceFailure => f.write_str("Failed to acess tdx attest device"),
            TdxError::ExtendFailure => f.write_str("Failed to extend rtmr"),
            TdxError::Interrupted => f.write_str("Usercall is interrupted"),
            TdxError::InvalidCpuSvn => f.write_str("Failed to verify TD report: invalid Cpu Svn"),
            TdxError::InvalidParameter => f.write_str("The parameter is incorrect"),
            TdxError::InvalidReportMacStruct => f.write_str("Failed to verify TD report: invalid ReportMac"),
            TdxError::InvalidRtmrIndex => f.write_str("Only supported RTMR index is 2 and 3"),
            TdxError::NotSupported => f.write_str("Request feature is not supported"),
            TdxError::OutOfMemory => f.write_str("Not enough memory is available to complete this operation"),
            TdxError::QuoteFailure => f.write_str("Failed to get the TD Quote"),
            TdxError::ReportFailure => f.write_str("Failed to get the TD Report"),
            TdxError::TdcallFailure => f.write_str("TD call failed"),
            TdxError::UnsupportedAttKeyId => f.write_str("The platform Quoting infrastructure does not support any of the keys described in att_key_id_list"),
            TdxError::VsockFailure => f.write_str("vsock related failure"),
            TdxError::WrongDevice => f.write_str("Unsupported device"),
            TdxError::Unexpected(num) => f.write_fmt(format_args!("Unexpected errno: {}", num)),
        }
    }
}

// TODO: Add TdxReportV2 support
/// Request a TDX Report of the calling TD.
/// Currently only support report with version number 0 or 1.
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
pub fn get_tdx_report(report_data: [u8; REPORT_DATA_SIZE]) -> Result<TdxReportV1, TdxError> {
    tdx_ioctl::get_report(report_data)
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
/// The [`get_report`] API may be used for this.
/// The input to this API includes a description of the “extend data”. This is
/// intended to facilitate reconstruction of the RTMR value. This, in turn,
/// suggests maintenance of an event log by the callee. Currently, event_data is
/// not supported.
pub fn extend_tdx_rtmr(
    rtmr_index: u64,
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_SIZE],
) -> Result<(), TdxError> {
    tdx_ioctl::extend_rtmr(rtmr_index, extend_data)
}

// Following mapping is based on Intel upstream code:
// https://github.com/intel-staging/tdx/blob/tdx-guest-v6.10-1/drivers/virt/coco/tdx-guest/tdx-guest.c
/// Map errno returned from ioctl when interact with kernel's TDX guest module.
pub fn errno_to_tdx_err(errno: Errno) -> TdxError {
    match errno {
        Errno::ENOMEM => TdxError::OutOfMemory,
        Errno::EFAULT => TdxError::BadAddress,
        Errno::EINTR => TdxError::Interrupted,
        Errno::EINVAL => TdxError::InvalidParameter,
        Errno::EIO => TdxError::TdcallFailure,
        Errno::EPERM => TdxError::InvalidRtmrIndex,
        Errno::EBUSY => TdxError::Busy,
        Errno::ENOTTY => TdxError::NotSupported,
        Errno::ENODEV => TdxError::WrongDevice,

        err => TdxError::Unexpected(err as u32),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tdx_att_get_report_invalid_device() {
        let result = get_tdx_report([0; REPORT_DATA_SIZE]);
        match result {
            Ok(_) => panic!("expecting error"),
            Err(err) => assert_eq!(err, TdxError::DeviceFailure),
        }
    }

    #[test]
    fn test_tdx_att_extend_invalid_device() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;
        let err = extend_tdx_rtmr(2, extend_data).expect_err("expecting err");
        assert_eq!(err, TdxError::DeviceFailure);
    }

    #[test]
    fn test_tdx_att_extend_invalid_index() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;

        let err = extend_tdx_rtmr(77, extend_data).expect_err("expecting err");
        assert_eq!(err, TdxError::InvalidRtmrIndex);
    }
}
