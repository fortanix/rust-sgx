use std::convert::From;
pub use tdx_module::{tdx_attest_error_t, tdx_report_data_t, tdx_report_t};
use thiserror::Error;
use super::TdxReport;

pub use tdx_module::tdx_att_get_report;

#[derive(Error, Debug)]
pub enum TdxAttestError {
    #[error("Indicate min error to allow better translation")]
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
    #[error("The platform Quoting infrastructure does not support any of the keys described in att_key_id_list")]
    UnsupportedAttKeyId,
}

impl From<TdxReport> for tdx_report_t {
    fn from(report: TdxReport) -> Self {
        tdx_report_t {
            d: report.0,
        }
    }
}

pub fn to_tdx_attest_error(err: tdx_attest_error_t) -> Result<(), TdxAttestError> {
    match err {
        tdx_attest_error_t::TDX_ATTEST_SUCCESS => Ok(()),
        tdx_attest_error_t::TDX_ATTEST_ERROR_MIN => Err(TdxAttestError::Min),
        tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER => Err(TdxAttestError::InvalidParameter),
        tdx_attest_error_t::TDX_ATTEST_ERROR_OUT_OF_MEMORY => Err(TdxAttestError::OutOfMemory),
        tdx_attest_error_t::TDX_ATTEST_ERROR_VSOCK_FAILURE => Err(TdxAttestError::VsockFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_REPORT_FAILURE => Err(TdxAttestError::ReportFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_EXTEND_FAILURE => Err(TdxAttestError::ExtendFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_NOT_SUPPORTED => Err(TdxAttestError::NotSupported),
        tdx_attest_error_t::TDX_ATTEST_ERROR_QUOTE_FAILURE => Err(TdxAttestError::QuoteFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_BUSY => Err(TdxAttestError::Busy),
        tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE => Err(TdxAttestError::DeviceFailure),
        tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_RTMR_INDEX => Err(TdxAttestError::InvalidRtmrIndex),
        tdx_attest_error_t::TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID => Err(TdxAttestError::UnsupportedAttKeyId),
        tdx_attest_error_t::TDX_ATTEST_ERROR_MAX => Err(TdxAttestError::InvalidParameter),
    }
}

