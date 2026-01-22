/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

//! ioctl-based TDX attestation backend.

use crate::{
    TDX_REPORT_DATA_SIZE, TDX_REPORT_SIZE, TDX_RTMR_EXTEND_DATA_SIZE, TdxAttestError, TdxReport,
};

const TDX_ATTEST_DEV_PATH: &str = "/dev/tdx_guest";

#[repr(C)]
struct TdxReportReq {
    report_data: [u8; TDX_REPORT_DATA_SIZE],
    td_report: [u8; TDX_REPORT_SIZE],
}

nix::ioctl_readwrite!(tdx_cmd_get_report, b'T', 1, TdxReportReq);

/// Request a TDX Report of the calling TD via ioctl on `/dev/tdx_guest`.
pub fn get_report(report_data: [u8; TDX_REPORT_DATA_SIZE]) -> Result<TdxReport, TdxAttestError> {
    use std::os::fd::AsRawFd;
    let mut req = TdxReportReq {
        report_data,
        td_report: [0u8; TDX_REPORT_SIZE],
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_ATTEST_DEV_PATH)
        .map_err(|_| TdxAttestError::DeviceFailure)?;

    unsafe { tdx_cmd_get_report(file.as_raw_fd(), &mut req) }
        .map_err(|_| TdxAttestError::ReportFailure)?;
    Ok(TdxReport::try_copy_from(&req.td_report).expect("validated size"))
}

#[repr(C)]
struct TdxExtendRtmrReq {
    data: [u8; TDX_RTMR_EXTEND_DATA_SIZE],
    index: u8,
}

nix::ioctl_readwrite!(tdx_cmd_extend_rtmr, b'T', 3, TdxExtendRtmrReq);

/// Extend one of the TDX runtime measurement registers (RTMRs) via ioctl on `/dev/tdx_guest`.
pub fn extend_rtmr(
    rtmr_index: u64,
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_SIZE],
) -> Result<(), TdxAttestError> {
    let rtmr_index = match rtmr_index {
        2..=3 => rtmr_index as u8,
        _ => return Err(TdxAttestError::InvalidRtmrIndex),
    };

    use std::os::fd::AsRawFd;
    let mut req = TdxExtendRtmrReq {
        data: extend_data,
        index: rtmr_index,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_ATTEST_DEV_PATH)
        .map_err(|_| TdxAttestError::DeviceFailure)?;

    unsafe { tdx_cmd_extend_rtmr(file.as_raw_fd(), &mut req) }.map_err(|errno| match errno {
        nix::errno::Errno::EINVAL => TdxAttestError::InvalidRtmrIndex,
        _ => TdxAttestError::ExtendFailure,
    })?;

    Ok(())
}
