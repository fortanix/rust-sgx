/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

//! Low-level TDX attestation bindings and error translation.
//!
//! This module re-exports the raw attestation FFI functions and provides
//! backend helpers for the `tdx-attest-rs` approach.

use crate::{
    TDX_REPORT_DATA_SIZE, TDX_REPORT_SIZE, TDX_RTMR_EXTEND_DATA_SIZE, TdxAttestError, TdxReport,
};

pub use tdx_module::tdx_att_extend;
pub use tdx_module::tdx_att_get_quote;
pub use tdx_module::tdx_att_get_report;
pub use tdx_module::tdx_att_get_supported_att_key_ids;
pub use tdx_module::{tdx_attest_error_t, tdx_report_data_t, tdx_report_t, tdx_rtmr_event_t};

/// Request a TDX Report of the calling TD using `tdx-attest-rs`.
pub fn get_report(report_data: [u8; TDX_REPORT_DATA_SIZE]) -> Result<TdxReport, TdxAttestError> {
    let mut tdx_report = tdx_report_t {
        d: [0; TDX_REPORT_SIZE],
    };
    let report_data = tdx_report_data_t { d: report_data };
    parse_tdx_attest_error(tdx_att_get_report(Some(&report_data), &mut tdx_report))?;
    Ok(tdx_report.into())
}

/// Extend one of the TDX runtime measurement registers (RTMRs) using `tdx-attest-rs`.
pub fn extend_rtmr(
    rtmr_index: u64,
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_SIZE],
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
    rtmr_event[12..12 + TDX_RTMR_EXTEND_DATA_SIZE].copy_from_slice(&extend_data);

    parse_tdx_attest_error(tdx_att_extend(&rtmr_event))
}

#[rustfmt::skip]
/// Translate a raw TDX attestation error into a Rust result.
pub fn parse_tdx_attest_error(err: tdx_attest_error_t) -> Result<(), TdxAttestError> {
    match err {
        tdx_attest_error_t::TDX_ATTEST_SUCCESS =>                       Ok(()),
        tdx_attest_error_t::TDX_ATTEST_ERROR_MIN =>                     Err(TdxAttestError::Min),
        tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER =>       Err(TdxAttestError::InvalidParameter),
        tdx_attest_error_t::TDX_ATTEST_ERROR_OUT_OF_MEMORY =>           Err(TdxAttestError::OutOfMemory),
        tdx_attest_error_t::TDX_ATTEST_ERROR_VSOCK_FAILURE =>           Err(TdxAttestError::VsockFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_REPORT_FAILURE =>          Err(TdxAttestError::ReportFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_EXTEND_FAILURE =>          Err(TdxAttestError::ExtendFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_NOT_SUPPORTED =>           Err(TdxAttestError::NotSupported),
        tdx_attest_error_t::TDX_ATTEST_ERROR_QUOTE_FAILURE =>           Err(TdxAttestError::QuoteFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_BUSY =>                    Err(TdxAttestError::Busy),
        tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE =>          Err(TdxAttestError::DeviceFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_RTMR_INDEX =>      Err(TdxAttestError::InvalidRtmrIndex),
        tdx_attest_error_t::TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID =>  Err(TdxAttestError::UnsupportedAttKeyId),
        tdx_attest_error_t::TDX_ATTEST_ERROR_MAX =>                     Err(TdxAttestError::Max),
    }
}

#[cfg(feature = "tdx-module")]
impl From<tdx_report_t> for TdxReport {
    fn from(report: tdx_report_t) -> Self {
        Self::try_copy_from(&report.d).expect("validated size")
    }
}

#[cfg(feature = "tdx-module")]
impl From<TdxReport> for tdx_report_t {
    fn from(report: TdxReport) -> Self {
        let mut d = [0u8; TDX_REPORT_SIZE];
        d.copy_from_slice(report.as_ref());
        tdx_report_t { d }
    }
}
