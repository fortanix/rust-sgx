pub mod tdx_attest;

use tdx_attest::{TdxAttestError, tdx_report_data_t, tdx_report_t};
use tdx_module::tdx_uuid_t;
pub use uuid::Uuid;

pub const TDX_REPORT_LEN: usize = 1024;
pub const TDX_REPORT_DATA_LEN: usize = 64;
const TDX_RTMR_EVENT_HEADER_LEN: usize = 68;
pub const TDX_RTMR_EXTEND_DATA_LEN: usize = 48;

/// The generated TDX Report
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TdxReport([u8; TDX_REPORT_LEN]);

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
    /// Create an empty report
    pub fn new() -> Self {
        Self([0; TDX_REPORT_LEN])
    }

    pub fn read_raw(&self) -> &[u8; TDX_REPORT_LEN] {
        &self.0
    }

    /// Request a TDX Report of the calling TD.
    ///
    /// # Param
    /// - **report_data**\
    ///   A set of data that the caller/TD wants to cryptographically bind to the Quote, typically a hash. May be all zeros for the Report data.
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
    pub fn new(raw: Vec<u8>) -> Self {
        Self(raw)
    }

    pub fn read_raw(&self) -> &[u8] {
        &self.0
    }

    /// Request a Quote of the calling TD.
    ///
    /// # Param
    /// - **report_data**
    ///   A TDX Report of the calling TD.
    /// - **attestation_key_ids**
    ///   List of the attestation key IDs supported by the Quote verifier.
    ///
    /// # Return on success
    /// Tuple of generated [`TdxReport`] & selected attestation key ID.
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
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TdxRtmrEvent {
    version: u32,
    rtmr_index: u64,
    extend_data: [u8; TDX_RTMR_EXTEND_DATA_LEN],
    event_type: u32,
    event_data: Vec<u8>,
}

impl TdxRtmrEvent {
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
