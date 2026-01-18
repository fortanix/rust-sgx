//! Safe(er) Rust wrappers for the TDX attestation APIs.
//!
//! This module exposes higher-level types around the raw TDX attestation
//! interfaces and mirrors the semantics described in the upstream TDX
//! attestation headers.

pub mod tdx_attest;

use tdx_attest::{TdxAttestError, tdx_report_data_t, tdx_report_t};
use tdx_module::tdx_uuid_t;
pub use uuid::Uuid;

/// Size of a TDX report in bytes.
pub const TDX_REPORT_LEN: usize = 1024;
/// Size of the report data field in bytes.
pub const TDX_REPORT_DATA_LEN: usize = 64;
const TDX_RTMR_EVENT_HEADER_LEN: usize = 68;
/// Size of the RTMR extend data field in bytes.
pub const TDX_RTMR_EXTEND_DATA_LEN: usize = 48;

/// The generated TDX Report returned by the TDX module.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TdxReport([u8; TDX_REPORT_LEN]);

/// A TDX Quote (opaque byte blob) returned by the platform quoting stack.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TdxQuote(Vec<u8>);

impl From<tdx_report_t> for TdxReport {
    fn from(report: tdx_report_t) -> Self {
        let tdx_report_t { d } = report;
        Self(d)
    }
}

impl From<TdxReport> for tdx_report_t {
    fn from(report: TdxReport) -> Self {
        tdx_report_t { d: report.0 }
    }
}

impl TdxReport {
    /// Create an empty report buffer.
    pub fn new() -> Self {
        Self([0; TDX_REPORT_LEN])
    }

    /// Return the raw report bytes.
    pub fn read_raw(&self) -> &[u8; TDX_REPORT_LEN] {
        &self.0
    }

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
    pub fn get_report(report_data: [u8; TDX_REPORT_DATA_LEN]) -> Result<TdxReport, TdxAttestError> {
        let mut tdx_report = tdx_report_t {
            d: [0; TDX_REPORT_LEN],
        };
        let report_data = tdx_report_data_t { d: report_data };
        tdx_attest::parse_tdx_attest_error(tdx_attest::tdx_att_get_report(
            Some(&report_data),
            &mut tdx_report,
        ))?;
        Ok(tdx_report.into())
    }
}

impl TdxQuote {
    /// Wrap a raw quote buffer returned by the platform.
    pub fn new(raw: Vec<u8>) -> Self {
        Self(raw)
    }

    /// Return the raw quote bytes.
    pub fn read_raw(&self) -> &[u8] {
        &self.0
    }

    /// Request a Quote of the calling TD.
    ///
    /// The caller provides report data intended to be cryptographically bound to
    /// the resulting Quote and an optional list of attestation key IDs supported
    /// by the verifier. If the list is empty, the platform default key ID is used.
    ///
    /// # Parameters
    /// - **report_data**: Data to cryptographically bind to the Quote.
    /// - **attestation_key_ids**: List of attestation key IDs supported by the
    ///   verifier.
    ///
    /// # Returns
    /// On success, returns the generated [`TdxQuote`] and the selected attestation
    /// key ID.
    ///
    /// # Errors
    /// Propagates the underlying TDX attestation error code.
    pub fn get_quote(
        report_data: [u8; TDX_REPORT_DATA_LEN],
        attestation_key_ids: Vec<Uuid>,
    ) -> Result<(Self, Uuid), TdxAttestError> {
        let mut att_key_id = tdx_uuid_t { d: [0; 16usize] };
        let report_data = tdx_report_data_t { d: report_data };
        let ids: Vec<tdx_uuid_t> = attestation_key_ids
            .into_iter()
            .map(|id| tdx_uuid_t { d: id.into_bytes() })
            .collect();
        let ids = if ids.is_empty() {
            None
        } else {
            Some(ids.as_slice())
        };
        let (err_code, quote_data) =
            tdx_attest::tdx_att_get_quote(Some(&report_data), ids, Some(&mut att_key_id), 0);
        match tdx_attest::parse_tdx_attest_error(err_code) {
            Ok(()) => Ok((
                Self(quote_data.expect("validated")),
                Uuid::from_bytes_ref(&att_key_id.d).to_owned(),
            )),
            Err(err) => Err(err),
        }
    }
}

/// RTMR event payload for extend operation.
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
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TdxRtmrEvent {
    version: u32,
    rtmr_index: u64,
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_LEN],
    event_type: u32,
    event_data: Vec<u8>,
}

impl TdxRtmrEvent {
    /// Build a new RTMR extend event.
    pub fn new(
        version: u32,
        rtmr_index: u64,
        extend_data: [u8; TDX_RTMR_EXTEND_DATA_LEN],
        event_type: u32,
        event_data: Vec<u8>,
    ) -> Self {
        Self {
            version,
            rtmr_index,
            extend_data,
            event_type,
            event_data,
        }
    }
}

impl TryFrom<TdxRtmrEvent> for Vec<u8> {
    type Error = TdxAttestError;

    fn try_from(value: TdxRtmrEvent) -> Result<Self, TdxAttestError> {
        let event_data_size =
            u32::try_from(value.event_data.len()).or(Err(TdxAttestError::InvalidParameter))?;
        let mut out = Vec::with_capacity(TDX_RTMR_EVENT_HEADER_LEN + value.event_data.len());
        out.extend(value.version.to_ne_bytes());
        out.extend(value.rtmr_index.to_ne_bytes());
        out.extend(value.extend_data);
        out.extend(value.event_type.to_ne_bytes());
        out.extend(event_data_size.to_ne_bytes());
        out.extend(value.event_data);
        Ok(out)
    }
}

/// Extend one of the TDX runtime measurement registers (RTMRs).
///
/// Please check doc of [`TdxRtmrEvent`] for details of input.
pub fn extend_rtmr(rtmr_event: TdxRtmrEvent) -> Result<(), TdxAttestError> {
    let bytes: Vec<u8> = rtmr_event.try_into()?;
    tdx_attest::parse_tdx_attest_error(tdx_attest::tdx_att_extend(&bytes))
}

/// Retrieve the list of attestation key IDs supported by the platform.
pub fn get_supported_tdx_attestation_key_ids() -> Result<Vec<Uuid>, TdxAttestError> {
    let (err_code, att_key_ids) = tdx_attest::tdx_att_get_supported_att_key_ids();
    tdx_attest::parse_tdx_attest_error(err_code)?;
    let ids = att_key_ids.ok_or(TdxAttestError::InvalidParameter)?;
    Ok(ids
        .into_iter()
        .map(|id| Uuid::from_bytes_ref(&id.d).to_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdx_att_get_report() {
        let result = TdxReport::get_report([0; TDX_REPORT_DATA_LEN]);
        assert!(matches!(result, Err(TdxAttestError::DeviceFailure)));
    }

    #[test]
    fn test_tdx_att_get_quote() {
        let result = TdxQuote::get_quote([0; TDX_REPORT_DATA_LEN], Vec::new());
        assert!(matches!(result, Err(TdxAttestError::DeviceFailure)));
    }

    #[test]
    fn test_tdx_att_extend() {
        let mut extend_data = [0u8; TDX_RTMR_EXTEND_DATA_LEN];
        extend_data[0] = 123;
        let rtmr_event = TdxRtmrEvent::new(1, 2, extend_data, 3, Vec::new());
        let result = extend_rtmr(rtmr_event);
        assert!(matches!(result, Err(TdxAttestError::DeviceFailure)));
    }

    #[test]
    fn test_tdx_att_get_supported_att_key_ids() {
        let result = get_supported_tdx_attestation_key_ids();
        assert!(result.is_ok());
        let ids = result.unwrap();
        println!("Supported attestation key id num: {}", ids.len());
        for id in ids {
            println!("Attestation key id: {}", id);
        }
    }
}
