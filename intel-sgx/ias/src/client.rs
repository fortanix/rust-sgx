/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::error::Error;
use std::str;

use url::Url;
use percent_encoding::percent_decode_str as urldecode;
use reqwest::{header::HeaderValue, RequestBuilder};
pub use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};

use pkix::pem::{PEM_CERTIFICATE, PemBlock, pem_to_der};

use crate::HexPrint;
use crate::api::{IasAdvisoryId, IasVersion, Unverified, VerifyAttestationEvidenceRequest, VerifyAttestationEvidenceResponse};
pub use crate::verifier::AttestationEmbeddedIasReport;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

trait RequestBuilderExt {
    fn apply_credentials(self, ias_client: &Client) -> Self;
}

trait HeaderMapExt {
    fn header<H: Header>(&self) -> Result<Option<H>>;
}

impl HeaderMapExt for reqwest::header::HeaderMap {
    fn header<H: Header>(&self) -> Result<Option<H>> {
        let mut it = self.get_all(H::NAME).iter();
        match (it.next(), it.next()) {
            (Some(v), None) => return H::from_value(v).map(Some).map_err(|_| format!("Failed to parse header {}", H::NAME).into()),
            (None, _) => return Ok(None),
            _ => return Err(format!("Multiple values for {} header", H::NAME).into())
        }
    }
}

trait Header: Sized {
    const NAME: &'static str;

    fn from_value(v: &HeaderValue) -> std::result::Result<Self, Box<dyn std::error::Error>>;
}

#[derive(Clone, Debug)]
pub struct IasVerificationResult {
    /// The raw report, used for signature verification
    pub raw_report: Vec<u8>,

    /// The deserialized report
    pub report: VerifyAttestationEvidenceResponse<Unverified>,

    /// Signature over the raw report
    pub signature: Vec<u8>,

    /// Certificate chain, DER format
    pub cert_chain: Vec<Vec<u8>>,

    pub advisory_url: Option<String>,
    pub advisory_ids: Vec<IasAdvisoryId>,
}

impl From<IasVerificationResult> for AttestationEmbeddedIasReport<'static, 'static, 'static, Unverified> {
    fn from(res: IasVerificationResult) -> AttestationEmbeddedIasReport<'static, 'static, 'static, Unverified> {
        let IasVerificationResult {
            raw_report,
            signature,
            cert_chain,
            ..
        } = res;
        AttestationEmbeddedIasReport::from(
            sgx_pkix::attestation::AttestationEmbeddedIasReport {
                http_body: raw_report.into(),
                report_sig: signature.into(),
                certificates: cert_chain.into_iter().map(Into::into).collect()
            }
        )
    }
}

impl Into<sgx_pkix::attestation::AttestationEmbeddedIasReport<'static, 'static, 'static>> for IasVerificationResult {
    fn into(self) -> sgx_pkix::attestation::AttestationEmbeddedIasReport<'static, 'static, 'static> {
        let IasVerificationResult {
            raw_report,
            signature,
            cert_chain,
            ..
        } = self;
        sgx_pkix::attestation::AttestationEmbeddedIasReport {
            http_body: raw_report.into(),
            report_sig: signature.into(),
            certificates: cert_chain.into_iter().map(Into::into).collect()
        }
    }
}

/// Implementation of `hyper::header::Header` for the X-IASReport-Signature
/// header returned by IAS. The header contains the base64-encoded RSA signature
/// on the attestation verification report contained in the response body. Refer
/// to the IAS API Specification.
#[derive(Clone, Debug)]
struct IasReportSignature(pub Vec<u8>);


impl Header for IasReportSignature {
    const NAME: &'static str = "X-IASReport-Signature";

    fn from_value(v: &HeaderValue) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(IasReportSignature(base64::decode(v.to_str()?)?))
    }
}

/// Implementation of `hyper::header::Header` for the
/// X-IASReport-Signing-Certificate header returned by IAS. The header contains
/// a urlencoded PEM-format certificate chain for the attestation verification
/// report signing key. Refer to the IAS API Specification.
#[derive(Clone, Debug)]
struct IasReportSigningCertificate(pub String);

impl Header for IasReportSigningCertificate {
    const NAME: &'static str = "X-IASReport-Signing-Certificate";

    fn from_value(v: &HeaderValue) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(IasReportSigningCertificate(urldecode(v.to_str()?).decode_utf8()?.into_owned()))
    }
}

/// Implementation of `hyper::header::Header` for the Advisory-URL
/// header returned by IAS. The header contains a URL for a page with
/// additional information on SGX-related security issues. Refer
/// to the IAS API Specification.
#[derive(Clone, Debug)]
struct AdvisoryUrl(pub String);

impl Header for AdvisoryUrl {
    const NAME: &'static str = "Advisory-URL";

    fn from_value(v: &HeaderValue) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(AdvisoryUrl(v.to_str()?.to_owned()))
    }
}

/// Implementation of `hyper::header::Header` for the Advisory-IDs
/// header returned by IAS. The header contains a list of Advisory IDs
/// referring to articles providing insight into SGX-related security
/// issues that may affect attested platform. Refer
/// to the IAS API Specification.
#[derive(Clone, Debug)]
struct AdvisoryIds(pub String);

impl Header for AdvisoryIds {
    const NAME: &'static str = "Advisory-IDs";

    fn from_value(v: &HeaderValue) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(AdvisoryIds(v.to_str()?.to_owned()))
    }
}

pub struct Client {
    url: Url,
    ias_path: String,
    subscription_key: Option<String>,
    inner: reqwest::Client,
}

static API_FTX_SPID: &'static str = "ftx/spid";
static API_SIGRL: &'static str = "sigrl/";
static API_REPORT: &'static str = "report";

pub struct ClientBuilder {
    subscription_key: Option<String>,
    has_identity: bool,
    use_alt: Option<bool>,
    ias_version: IasVersion,
    inner: reqwest::ClientBuilder,
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder::new_with_reqwest_builder(Default::default())
    }

    pub fn new_with_reqwest_builder(builder: reqwest::ClientBuilder) -> Self {
        ClientBuilder {
            subscription_key: None,
            has_identity: false,
            use_alt: None,
            ias_version: crate::api::LATEST_IAS_VERSION,
            inner: builder
        }
    }

    /// Whether to use “alternate” API paths. The default is to use alternate
    /// paths from IAS version 4 onwards. If you use subscription keys with IAS
    /// version 3, you'll probably also want to use alternate paths.
    ///
    /// Traditional paths are: `/attestation/sgx/v$N/$API`
    ///
    /// Alternate paths are: `/attestation/v$N/$API`
    pub fn use_alternate_api_path(mut self, use_alt: bool) -> Self {
        self.use_alt = Some(use_alt);
        self
    }

    pub fn ias_version(mut self, version: IasVersion) -> Self {
        self.ias_version = version;
        self
    }

    pub fn subscription_key(mut self, subscription_key: String) -> Self {
        assert!(!self.has_identity);
        self.subscription_key = Some(subscription_key);
        self
    }

    #[cfg(feature = "client-certificate")]
    pub fn client_certificate(mut self, identity: reqwest::tls::Identity) -> Self {
        assert!(self.subscription_key.is_none());
        self.inner = self.inner.identity(identity);
        self.has_identity = true;
        self
    }

    /// Build the client, specifying the API root URL. The root is everything
    /// before `/attestation/...`
    pub fn build<U: IntoUrl>(self, url: U) -> Result<Client> {
        // make sure this is an HTTP(S) URL ending in a slash
        let mut url = url.into_url()?;
        if !(url.scheme() == "https" || url.scheme() == "http") || url.cannot_be_a_base() {
            return Err("IAS URL is not a valid HTTPS URL.".into());
        }
        if !url.path().ends_with("/") {
            url.path_segments_mut().expect("checked for cannot be a base").push("");
        }

        let alt = if self.use_alt.unwrap_or(self.ias_version >= IasVersion::V4) { "" } else { "sgx/" };
        let ias_path = format!("attestation/{}v{}/", alt, self.ias_version as u64);

        Ok(Client {
            url,
            ias_path,
            subscription_key: self.subscription_key,
            inner: self.inner.build()?
        })
    }
}

impl RequestBuilderExt for RequestBuilder {
    fn apply_credentials(self, ias_client: &Client) -> Self {
        if let Some(ref subscription_key) = ias_client.subscription_key {
            self.header("Ocp-Apim-Subscription-Key", subscription_key)
        } else {
            self
        }
    }
}

impl Client {
    /// Call the “Get SPID” API.
    ///
    /// This is a Fortanix extension used by the Fortanix IAS proxy.
    pub async fn get_spid(&self, report: &[u8]) -> Result<Vec<u8>> {
        let res = self.inner.post(self.url.join(API_FTX_SPID)?)
            .header("Accept", "application/octet-stream")
            .header("Content-Type", "application/octet-stream")
            .body(report.to_owned())
            .send().await?
            .error_for_status()?;

        Ok((*res.bytes().await?).into())
    }

    /// Call the “Retrieve SigRL” API.
    ///
    /// If `spid` is `None`, this is the standard IAS API. If `spid` is `Some`,
    /// as a Fortanix extension used by the Fortanix IAS proxy, the `spid` will
    /// be passed in a query parameter.
    pub async fn get_sig_rl(&self, gid: &[u8], spid: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut url = self.url
            .join(&self.ias_path)?
            .join(API_SIGRL)?
            .join(&HexPrint(&gid).to_string())?;
        if let Some(spid) = spid {
            url.query_pairs_mut().append_pair("spid", &HexPrint(&spid).to_string());
        }

        let res = self.inner.get(url)
            .apply_credentials(self)
            .header("Accept", "application/json")
            .send().await?
            .error_for_status()?;

        Ok((*res.bytes().await?).into())
    }

    /// Call the “Verify Attestation Evidence” API.
    ///
    /// This is the standard IAS API.
    pub async fn verify_quote(&self, quote: &[u8]) -> Result<IasVerificationResult> {
        let req = VerifyAttestationEvidenceRequest {
            isv_enclave_quote: quote.to_owned(),
            pse_manifest: None,
            nonce: None,
        };

        // serde JSON serialize, but binary data is Base64-encoded strings
        let mut json = vec![];
        let mut ser = serde_json::Serializer::new(&mut json);
        let ser = serde_bytes_repr::ByteFmtSerializer::base64(&mut ser, base64::Config::new(base64::CharacterSet::Standard, true));
        req.serialize(ser).map_err(|e| format!("Error serializing JSON request: {}", e))?;

        let res = self.inner.post(self.url.join(&self.ias_path)?.join(API_REPORT)?)
            .apply_credentials(self)
            .body(json)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send().await?
            .error_for_status()?;

        let signature: Vec<u8> = res.headers().header::<IasReportSignature>()?
            .ok_or_else(|| {
                format!("no {} header in response", IasReportSignature::NAME)
            })?
            .0;

        let cert_chain: String = res.headers().header::<IasReportSigningCertificate>()?
            .ok_or_else(|| {
                format!("no {} header in response", IasReportSigningCertificate::NAME)
            })?
            .0;

        // IAS returns a PEM-format cert chain in a header. Split the chain and convert to DER.
        let split_certs = PemBlock::new(cert_chain.as_bytes())
            .map(|c| {
                str::from_utf8(c).map_err(Into::into).and_then(|c| {
                    pem_to_der(c, Some(PEM_CERTIFICATE))
                        .ok_or_else(|| { "invalid PEM in report signing certificate chain".into() })
                })
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;

        let mut advisory_url = res.headers().header::<AdvisoryUrl>()?.map( |v| v.0 );
        let advisory_ids = res.headers().header::<AdvisoryIds>()?.map( |v| v.0 );

        // We need to keep a copy of the literal response body JSON to use for
        // signature verification.
        let raw_report = res.bytes().await?; // consumes the response

        debug!("Report body: {}", str::from_utf8(&raw_report).unwrap_or("<invalid UTF-8>"));

        // serde JSON deserialize, but binary data is Base64-encoded strings
        let mut deser = serde_json::Deserializer::from_slice(&raw_report);
        let deser = serde_bytes_repr::ByteFmtDeserializer::new_base64(&mut deser, base64::Config::new(base64::CharacterSet::Standard, true));
        let report = VerifyAttestationEvidenceResponse::deserialize(deser).map_err(|e| format!("Error deserializing JSON response: {}", e))?;

        // Prior to API documentation v6.0, advisory_url and advisory_ids
        // were returned in headers instead of the report itself
        match (&advisory_url, &report.advisory_url) {
            (None, Some(new_advisory_url)) => advisory_url = Some(new_advisory_url.clone()),
            _ => {}
        }

        let advisory_ids = match (advisory_ids, &report.advisory_ids) {
            (Some(advs), None) => advs.split(',').map(|adv| IasAdvisoryId::from(adv)).collect(),
            (None, Some(advs)) => advs.clone(),
            (None, None) => Vec::new(),
            _ => panic!("IAS service returned AdvisoryIds in the report and as a header"),
        };

        Ok(IasVerificationResult {
            raw_report: (*raw_report).into(),
            report,
            signature,
            cert_chain: split_certs,
            advisory_url,
            advisory_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These need to be filled in with appropriate values.
    const GID: &'static [u8] = b"";
    const SPID: &'static [u8] = b"";
    const IAS_URL: &'static str = "";
    const SUBSCRIPTION_KEY: &'static str = "";
    const QUOTE: &'static str = "";

    // To run this test you need to configure GID, SPID, and IAS_URL above.
    #[tokio::test]
    #[ignore]
    async fn test_get_sig_rl() {
        let client = ClientBuilder::new()
            .ias_version(IasVersion::V3)
            .build(IAS_URL).unwrap();
        let _ = client.get_sig_rl(&GID, Some(&SPID)).await.unwrap();
    }

    // To run this test you need to configure GID, SPID, IAS_URL, and SUBSCRIPTION_KEY above.
    #[tokio::test]
    #[ignore]
    async fn test_get_sig_rl_v4() {
        let client = ClientBuilder::new()
            .ias_version(IasVersion::V4)
            .subscription_key(SUBSCRIPTION_KEY.into())
            .build(IAS_URL).unwrap();
        let _ = client.get_sig_rl(&GID, Some(&SPID)).await.unwrap();
    }

    // To run this test you need to configure QUOTE and IAS_URL above.
    #[tokio::test]
    #[ignore]
    async fn test_verify_quote_v3_old() {
        let client = ClientBuilder::new()
            .ias_version(IasVersion::V3)
            .build(IAS_URL).unwrap();
        let _ = client.verify_quote(&base64::decode(&QUOTE).unwrap()).await.unwrap();
    }

    // To run this test you need to configure QUOTE, IAS_URL, and SUBSCRIPTION_KEY above.
    #[tokio::test]
    #[ignore]
    async fn test_verify_quote_v3() {
        let client = ClientBuilder::new()
            .ias_version(IasVersion::V3)
            .use_alternate_api_path(true)
            .subscription_key(SUBSCRIPTION_KEY.into())
            .build(IAS_URL).unwrap();
        let _ = client.verify_quote(&base64::decode(&QUOTE).unwrap()).await.unwrap();
    }

    // To run this test you need to configure QUOTE, IAS_URL, and SUBSCRIPTION_KEY above.
    #[tokio::test]
    #[ignore]
    async fn test_verify_quote_v4() {
        let client = ClientBuilder::new()
            .ias_version(IasVersion::V4)
            .subscription_key(SUBSCRIPTION_KEY.into())
            .build(IAS_URL).unwrap();
        let _ = client.verify_quote(&base64::decode(&QUOTE).unwrap()).await.unwrap();
    }
}
