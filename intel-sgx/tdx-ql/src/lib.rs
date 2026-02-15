/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

#![doc = include_str!("../README.md")]

use sgx_isa::tdx::TdxAttestErrorCode;
pub use sgx_isa::tdx::{TDX_REPORT_DATA_SIZE, TDX_REPORT_SIZE, TdxReport, TdxReportV1, TdxReportV2};

pub mod tdx_ioctl;

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
pub fn get_tdx_report(
    report_data: [u8; TDX_REPORT_DATA_SIZE],
) -> Result<TdxReportV1, TdxAttestErrorCode> {
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
) -> Result<(), TdxAttestErrorCode> {
    tdx_ioctl::extend_rtmr(rtmr_index, extend_data)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tdx_att_get_report_invalid_device() {
        let result = get_tdx_report([0; TDX_REPORT_DATA_SIZE]);
        match result {
            Ok(_) => panic!("expecting error"),
            Err(err) => assert_eq!(err, TdxAttestErrorCode::DeviceFailure),
        }
    }

    #[test]
    fn test_tdx_att_extend_invalid_device() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;
        let err = extend_tdx_rtmr(2, extend_data).expect_err("expecting err");
        assert_eq!(err, TdxAttestErrorCode::DeviceFailure);
    }

    #[test]
    fn test_tdx_att_extend_invalid_index() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_SIZE];
        extend_data[0] = 123;

        let err = extend_tdx_rtmr(77, extend_data).expect_err("expecting err");
        assert_eq!(err, TdxAttestErrorCode::InvalidRtmrIndex);
    }
}
