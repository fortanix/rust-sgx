#[cfg(feature="tdx_module")]
mod tdx_module;

#[cfg(feature="tdx_module")]
use tdx_module::{TdxAttestError, tdx_report_t};

const TDX_REPORT_LEN: usize = 1024;

#[derive(PartialEq, Eq, Debug)]
pub struct TdxReport([u8; TDX_REPORT_LEN]);

#[cfg(feature="tdx_module")]
impl From<tdx_report_t> for TdxReport {
    fn from(report: tdx_report_t) -> TdxReport {
        let tdx_report_t { d } = report;
        TdxReport(d)
    }
}

impl TdxReport {
    pub fn new() -> Self {
        TdxReport([0; TDX_REPORT_LEN])
    }

    #[cfg(feature="tdx_module")]
    pub fn get_report(report_data: [u8; 64]) -> Result<TdxReport, TdxAttestError> {
        let mut tdx_report =  tdx_report_t {
            d: [0; 1024],
        };
        let report_data = tdx_module::tdx_report_data_t {
            d: report_data
        };
        tdx_module::to_tdx_attest_error(tdx_module::tdx_att_get_report(Some(&report_data), &mut tdx_report))?;
        Ok(tdx_report.into())
    }
}

