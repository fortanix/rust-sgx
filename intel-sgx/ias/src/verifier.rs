/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::api::{EnclaveQuoteBody, IasAdvisoryId, IasVersion, PlatformStatus, QuoteStatus,
    SUPPORTED_IAS_VERSIONS, Unverified, Verified, VerificationType, VerifyAttestationEvidenceResponse};
use serde::Deserialize;
use serde_bytes_repr::ByteFmtDeserializer;
#[cfg(feature = "manipulate_attestation")]
use std::str::FromStr;
use std::convert::TryInto;
use std::marker::PhantomData;
use once_cell::sync::Lazy;
use pkix::{ASN1Result, DerWrite, FromDer};
use pkix::derives::{BERDecodable, BERReader, DERWriter};
use pkix::x509::GenericCertificate;
use sgx_isa::{Attributes, AttributesFlags, Miscselect};
#[cfg(target_env = "sgx")]
use sgx_isa::Report;
use sgx_pkix::oid;
use std::fmt;
use std::result::Result;

pub mod crypto;
pub use self::crypto::private::Crypto;

pub static MITIGATED_SECURITY_ADVISORIES: Lazy<Vec<IasAdvisoryId>> = Lazy::new(|| {
    #[allow(unused_mut)]
    let mut v: Vec<IasAdvisoryId> = Vec::new();

    #[cfg(intel_sa_00334)]
    v.push(IasAdvisoryId::from("INTEL-SA-00334"));

    #[cfg(intel_sa_00615)]
    v.push(IasAdvisoryId::from("INTEL-SA-00615"));

    v
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveIdentity {
    pub mrenclave: Vec<u8>,
    pub mrsigner: Vec<u8>,
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub attributes: Attributes,
    pub miscselect: Miscselect,
}

impl From<EnclaveQuoteBody> for EnclaveIdentity {
    fn from(quote: EnclaveQuoteBody) -> EnclaveIdentity {
        EnclaveIdentity {
            mrenclave: quote.mrenclave.to_vec(),
            mrsigner: quote.mrsigner.to_vec(),
            isvprodid: quote.isvprodid,
            isvsvn: quote.isvsvn,
            attributes: quote.attributes.clone(),
            miscselect: quote.miscselect,
        }
    }
}

#[derive(Debug)]
pub struct Error {
    pub error_kind: ErrorKind,
    pub cause: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    // This is a helper that exists for legacy reasons. It is not really necessary,
    // the errors could be constructed directly.
    pub fn enclave_certificate<E>(error_kind: ErrorKind, cause: Option<E>) -> Error
        where E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        Error {
            error_kind,
            cause: cause.map(Into::into),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("enclave certificate verification error: {}", self.error_kind))?;
        if let Some(ref err) = self.cause {
            f.write_fmt(format_args!(": {}", err))?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.cause.as_ref().map(|b| &**b as _)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Asn1InvalidBitstring,
    Asn1NotBytes,
    CaNotConfigured,
    MissingIasReport,
    ReportAsn1Parse,
    ReportJsonParse,
    ReportBadQuoteSize,
    SpkiHashFailure,
    ReportNoCertificate,
    ReportInvalidCertificate,
    ReportUntrustedCertificate,
    ReportBadSignature,
    ReportBadQuoteStatus(QuoteStatus, Option<Result<PlatformStatus, String>>),
    ReportBadPayload,
    ReportBadVersion { actual: u64 },
    ReportUnsupportedVersion { actual: IasVersion, supported: Vec<IasVersion> },
    MrsignerMismatch { local: Vec<u8>, remote: Vec<u8> },
    IsvprodidMismatch { local: u16, remote: u16 },
    FlagsMismatch { local: AttributesFlags, remote: AttributesFlags },
    XfrmMismatch { local: u64, remote: u64 },
    MiscselectMismatch { local: Miscselect, remote: Miscselect },
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ErrorKind::*;
        match *self {
            Asn1InvalidBitstring => f.write_fmt(format_args!("ASN.1 bitstring is not a multiple of bytes")),
            Asn1NotBytes => f.write_fmt(format_args!("ASN.1 value is not a bitstring or octetstring")),
            CaNotConfigured => f.write_fmt(format_args!("at least one CA certificate is required")),
            MissingIasReport => f.write_fmt(format_args!("no IAS report extension in certificate")),
            ReportAsn1Parse => f.write_fmt(format_args!("unable to parse report ASN.1")),
            ReportJsonParse => f.write_fmt(format_args!("unable to parse report JSON")),
            ReportBadQuoteSize => f.write_fmt(format_args!("invalid size of enclave quote body")),
            SpkiHashFailure => f.write_fmt(format_args!("error computing SPKI hash")),
            ReportNoCertificate => f.write_fmt(format_args!("no signing certificates in report")),
            ReportInvalidCertificate => f.write_fmt(format_args!("invalid signing certificate in report")),
            ReportUntrustedCertificate => f.write_fmt(format_args!("server report signing certificate is not trusted")),
            ReportBadSignature => f.write_fmt(format_args!("bad report signature")),
            ReportBadQuoteStatus(qstatus, ref pstatus) => f.write_fmt(format_args!("bad quote status in report: {:?}{}", qstatus,
                match *pstatus {
                    Some(Ok(ref pstatus)) => format!(" ({})", pstatus),
                    Some(Err(ref e)) => format!(" (failed to parse platform info blob {})", e),
                    None => String::new(),
                }
            )),
            ReportBadPayload => f.write_fmt(format_args!("SPKI does not match REPORTDATA")),
            ReportBadVersion { actual } => f.write_fmt(format_args!("invalid version {}", actual)),
            ReportUnsupportedVersion { actual, ref supported } => f.write_fmt(format_args!("report version {} is not supported, supported versions are {:?}", actual as u64, supported)),
            MrsignerMismatch { ref local, ref remote } => f.write_fmt(format_args!("enclave peer mrsigner mismatch, local = {}, remote = {}",
                                                                                   crate::HexPrint(&local), crate::HexPrint(&remote))),
            IsvprodidMismatch { local, remote } => f.write_fmt(format_args!("enclave peer isvprodid mismatch, local = {}, remote = {}",
                                                                            local, remote)),
            FlagsMismatch { local, remote } =>
                f.write_fmt(format_args!("enclave peer attributes.flags mismatch, masked local = {:?}, masked remote = {:?}",
                                         local, remote)),
            XfrmMismatch { local, remote } =>
                f.write_fmt(format_args!("enclave peer attributes.xfrm mismatch, masked local = {}, masked remote = {}",
                                         local, remote)),
            MiscselectMismatch { local, remote } =>
                f.write_fmt(format_args!("enclave peer miscselect mismatch, masked local = {:?}, masked remote = {:?}",
                                         local, remote)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttestationEmbeddedIasReport<'a, 'b, 'c, V: VerificationType = Verified> {
    report: sgx_pkix::attestation::AttestationEmbeddedIasReport<'a, 'b, 'c>,
    type_: PhantomData<V>,
}

impl<'a, 'b, 'c> From<sgx_pkix::attestation::AttestationEmbeddedIasReport<'a, 'b, 'c>> for AttestationEmbeddedIasReport<'a, 'b, 'c, Unverified> {
    fn from(report: sgx_pkix::attestation::AttestationEmbeddedIasReport<'a, 'b, 'c>) -> Self {
        AttestationEmbeddedIasReport {
            report,
            type_: PhantomData::<Unverified>,
        }
    }
}

impl<'a, 'b, 'c> Into<sgx_pkix::attestation::AttestationEmbeddedIasReport<'a, 'b, 'c>> for AttestationEmbeddedIasReport<'a, 'b, 'c, Unverified> {
    fn into(self) -> sgx_pkix::attestation::AttestationEmbeddedIasReport<'a, 'b, 'c> {
        self.report
    }
}

impl<'a, 'b, 'c, V: VerificationType> DerWrite for AttestationEmbeddedIasReport<'a, 'b, 'c, V> {
    fn write(&self, writer: DERWriter) {
        self.report.write(writer)
    }
}

impl BERDecodable for AttestationEmbeddedIasReport<'static, 'static, 'static, Unverified> {
    fn decode_ber<'p, 'q>(reader: BERReader<'p, 'q>) -> ASN1Result<Self> {
        Ok(AttestationEmbeddedIasReport {
            report: sgx_pkix::attestation::AttestationEmbeddedIasReport::decode_ber(reader)?,
            type_: PhantomData::<_>,
        })
    }
}

impl<'a, 'b, 'c> AttestationEmbeddedIasReport<'a, 'b, 'c, Unverified> {
    /// Verify that the ias report is correctly signed by one of the keys belonging to the certificates in `report_signing_ca`
    ///
    /// This function only verifies that the report itself is signed directly by one of the CAs. It does NOT verify the report contents.
    /// The report may indicated that the platform is out of date, or even relate to a different than the expected enclave.
    pub fn verify<C: Crypto>(self, report_signing_ca: &[&[u8]]) -> Result<AttestationEmbeddedIasReport<'a, 'b, 'c>, Error> {
        // TODO: check the validity of the chain, and use the CA as the trust
        // anchor rather than the leaf. Chain verification outside the context
        // of TLS connection establishment does not seem to be exposed by
        // either the rust openssl or mbedtls bindings.

        let AttestationEmbeddedIasReport::<Unverified> {
            report,
            type_: _,
        } = self;

        let leaf_cert = match report.certificates.first() {
            None => return Err(Error::enclave_certificate(ErrorKind::ReportNoCertificate, None::<Error>)),
            Some(cert) => GenericCertificate::from_der(cert)
                .map_err(|e| Error::enclave_certificate(ErrorKind::ReportInvalidCertificate, Some(e)))?,
        };

        if report_signing_ca.len() == 0 {
            return Err(Error::enclave_certificate(ErrorKind::CaNotConfigured, None::<Error>));
        }

        // Verify that the leaf cert appears in our list of trusted certificates
        if !report_signing_ca.iter().map(GenericCertificate::from_der)
            .any(|c| match c {
                Ok(ref c) if c == &leaf_cert => true,
                _ => false
            }) {
            return Err(Error::enclave_certificate(ErrorKind::ReportUntrustedCertificate, None::<Error>));
        }

        C::rsa_sha256_verify(leaf_cert.tbscert.spki.as_ref(), &report.http_body, &report.report_sig)
            .map_err(|e| Error::enclave_certificate(ErrorKind::ReportBadSignature, Some(e)))?;

        Ok(AttestationEmbeddedIasReport{
            report,
            type_: PhantomData::<Verified>,
        })
    }

    pub fn quote<C: Crypto, P: Platform>(self, report_signing_ca: &[&[u8]], platform_verifier: &P) -> Result<EnclaveQuoteBody, Error> {
        Ok(self.verify::<C>(report_signing_ca)?
            .to_attestation_evidence_reponse()?
            .verify(platform_verifier)?
            .isv_enclave_quote_body())
    }
}

impl<'a, 'b, 'c, V: VerificationType> AttestationEmbeddedIasReport<'a, 'b, 'c, V> {
    pub fn to_attestation_evidence_reponse(&self) -> Result<VerifyAttestationEvidenceResponse<Unverified>, Error> {
        let mut json_de = serde_json::Deserializer::from_slice(&self.report.http_body);
        let base64_config = base64::Config::new(base64::CharacterSet::Standard, true);
        let bytefmt_json_de = ByteFmtDeserializer::new_base64(&mut json_de, base64_config);
        VerifyAttestationEvidenceResponse::deserialize(bytefmt_json_de)
            .map_err(|e| Error::enclave_certificate(ErrorKind::ReportJsonParse, Some(e)))
    }
}

/// Check that `cert` contains the `AttestationEmbeddedIasReport` X.509 extension and that the
/// report in that extension:
///
///  * has a valid signature from a trusted report signer
///  * reports a valid attestation
///  * had REPORTDATA containing the hash of `cert`'s SubjectPublicKeyInfo
///
/// If the checks pass, returns `Ok(EnclaveIdentity { ... })` with the enclave identity from the
/// validated report. This proves that the enclave identified by the result of this function owns
/// the key belonging to the certificate `cert`. If the checks do not pass, returns an error.
///
/// `report_signing_ca` is a list of certificates trusted to directly sign the embedded IAS report, not the
/// certificates trusted to sign `cert`.
///
/// CAUTION: This routine does not verify the certificate signature nor the standard X.509
/// attributes. The caller is responsible for that.
pub fn verify_epid_cert_embedded_attestation<C: Crypto, P: Platform>(report_signing_ca: &[&[u8]], cert: &GenericCertificate, platform_verifier: &P) -> Result<EnclaveIdentity, Error> {
    let extn = cert.tbscert.get_extension(&oid::attestationEmbeddedIasReport)
        .ok_or_else(|| Error::enclave_certificate(ErrorKind::MissingIasReport, None::<Error>))?;

    // The extension is stored as a DER octetstring
    let quote = AttestationEmbeddedIasReport::from_der(&extn.value)
        .map_err(|e| Error::enclave_certificate(ErrorKind::ReportAsn1Parse, Some(e)))?
        .quote::<C, _>(report_signing_ca, platform_verifier)?;

    // The SGX report data must contain the SPKI hash.
    let mut expected_reportdata = [0; crypto::SHA256_DIGEST_LEN];
    C::sha256(cert.tbscert.spki.as_ref(), &mut expected_reportdata)
        .map_err(|e| Error::enclave_certificate(ErrorKind::SpkiHashFailure, Some(e)))?;
    let mut expected_reportdata = Vec::from(expected_reportdata);
    expected_reportdata.resize(::std::mem::size_of_val(&quote.reportdata), 0);

    if expected_reportdata != &quote.reportdata[..] {
        return Err(Error::enclave_certificate(ErrorKind::ReportBadPayload, None::<Error>));
    }

    Ok(quote.into())
}

pub fn is_supported(ias_version: IasVersion) -> bool {
    let supported = SUPPORTED_IAS_VERSIONS.to_vec();
    supported.contains(&ias_version)
}

pub trait Platform {
    fn verify(&self, for_self: bool, nonce: &Option<String>, isv_enclave_quote_status: QuoteStatus, advisories: &Vec<IasAdvisoryId>) -> Result<(), Error>;
}

pub struct AutoDetect;

impl AutoDetect {
    pub fn new() -> AutoDetect {
        AutoDetect {}
    }
}

impl Platform for AutoDetect {
    fn verify(&self, for_self: bool, _nonce: &Option<String>, isv_enclave_quote_status: QuoteStatus, advisories: &Vec<IasAdvisoryId>) -> Result<(), Error> {
        // The report must be for a valid quote.
        match (for_self, isv_enclave_quote_status) {
            (false, QuoteStatus::SwHardeningNeeded) => {
                /* We don't know how the enclave peer has been compiled. Enclaves may verify their own
                 * attestations, so we can ignore `QuoteStatus::SwHardeningNeeded` here and rely on the
                 * logic of enclave versions. It is of paramount importance that we only ignore
                 * `QuoteStatus::SwHardeningNeeded` cases.
                 * `QuoteStatus::ConfigurationAndSwHardeningNeeded` means that the platform itself
                 * needs to be updated as well. (Advisory IDs on how to do this will be included in the
                 * `report.advisory_ids`) Such attestations should *always* be rejected. */
                Ok(())
            },
            (true, QuoteStatus::SwHardeningNeeded) => {
                /* Lets the enclave verify its own attestation. This enables us to inspect the compiler
                 * used, and verify all software mitigations are in place. Quotes with status
                 * `QuoteStatus::ConfigurationAndSwHardeningNeeded` represent insecure platforms and
                 * should always be rejected. */
                if advisories
                    .iter()
                    .any(|adv| !MITIGATED_SECURITY_ADVISORIES.contains(adv)) {
                    let missing_ids = advisories
                        .iter()
                        .filter_map(|id|
                            if MITIGATED_SECURITY_ADVISORIES.contains(id) {
                                None
                            } else {
                                Some(id.as_str().to_string())
                            })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Err(Error{
                        error_kind: ErrorKind::ReportBadQuoteStatus(isv_enclave_quote_status, None),
                        cause: Some(format!("Not all security advisories are mitigated. Missing mitigations: {}", missing_ids).into()),
                    })
                } else {
                    Ok(())
                }
            },
            (_, QuoteStatus::Ok) => {
                Ok(())
            },
            _ => {
                Err(Error{
                    error_kind: ErrorKind::ReportBadQuoteStatus(isv_enclave_quote_status, None),
                    cause: Some(format!("Quote status of {:?} is not trustworthy", isv_enclave_quote_status).into()),
                })
            },
        }
    }
}

impl VerifyAttestationEvidenceResponse<Unverified> {
    #[cfg(feature = "manipulate_attestation")]
    fn manipulate_attestation(self) -> Self {
        let mut resp = self.clone();

        if let Some(extra_advisories) = option_env!("IAS_EXTRA_ADVISORIES") {
            let mut extra_advisories: Vec<IasAdvisoryId> = extra_advisories
                .split(",")
                .map(|adv| IasAdvisoryId::from(adv))
                .collect();

            if let Some(advisory_ids) = resp.advisory_ids.as_mut() {
                advisory_ids.append(&mut extra_advisories);
            } else {
                resp.advisory_ids = Some(extra_advisories)
            }
        }

        if let Some(status) = option_env!("IAS_QUOTE_STATUS") {
            resp.isv_enclave_quote_status = QuoteStatus::from_str(status).expect("Failed to parse SET_QUOTE_STATUS environment variable value");
        }

        resp
    }

    pub fn verify<P: Platform>(self, platform_verifier: &P) -> Result<VerifyAttestationEvidenceResponse, Error> {
        #[cfg(feature = "manipulate_attestation")]
        let resp = self.manipulate_attestation();

        #[cfg(not(feature = "manipulate_attestation"))]
        let resp = self;

        let VerifyAttestationEvidenceResponse::<Unverified> {
            id,
            timestamp,
            version,
            isv_enclave_quote_status,
            isv_enclave_quote_body,
            revocation_reason,
            pse_manifest_status,
            pse_manifest_hash,
            platform_info_blob,
            nonce,
            epid_pseudonym,
            advisory_url,
            advisory_ids,
            type_: _,
        } = resp;

        // The report must be generated by the supported IAS version's
        match version.try_into() {
            Ok(actual) => {
                if !is_supported(actual) {
                    let supported = SUPPORTED_IAS_VERSIONS.to_vec();
                    return Err(Error::enclave_certificate(ErrorKind::ReportUnsupportedVersion { actual, supported }, None::<Error>));
                }
            },
            Err(_) => {
                return Err(Error::enclave_certificate(ErrorKind::ReportBadVersion { actual: version }, None::<Error>));
            }
        }

        let _quote = EnclaveQuoteBody::try_copy_from(&isv_enclave_quote_body)
            .ok_or(Error::enclave_certificate(ErrorKind::ReportBadQuoteSize, None::<Error>))?;

        #[cfg(target_env = "sgx")]
        let for_self = {
            let report_self = Report::for_self();
            report_self.mrenclave == _quote.mrenclave && report_self.mrsigner == _quote.mrsigner
        };

        #[cfg(not(target_env = "sgx"))]
        let for_self = false;

        platform_verifier.verify(for_self, &nonce, isv_enclave_quote_status, advisory_ids.as_ref().unwrap_or(&Vec::new()))?;

        Ok(VerifyAttestationEvidenceResponse {
            id,
            timestamp,
            version,
            isv_enclave_quote_status,
            isv_enclave_quote_body,
            revocation_reason,
            pse_manifest_status,
            pse_manifest_hash,
            platform_info_blob,
            nonce,
            epid_pseudonym,
            advisory_url,
            advisory_ids,
            type_: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature="mbedtls")]
    use {
        once_cell::sync::Lazy,
        pkix::ToDer,
        pkix::pem::{self, PEM_CERTIFICATE},
        std::borrow::Cow,
        super::crypto::Mbedtls,
    };
    use crate::api::{IasAdvisoryId, VerifyAttestationEvidenceResponse};

    struct NoSwMitigationInPlace;

    impl NoSwMitigationInPlace {
        pub fn new() -> NoSwMitigationInPlace {
            NoSwMitigationInPlace {}
        }
    }

    impl Platform for NoSwMitigationInPlace {
        fn verify(&self, _for_self: bool, _nonce: &Option<String>, isv_enclave_quote_status: QuoteStatus, _advisories: &Vec<IasAdvisoryId>) -> Result<(), Error> {
            match isv_enclave_quote_status {
                QuoteStatus::Ok => Ok(()),
                QuoteStatus::SwHardeningNeeded =>
                    Err(Error{
                        error_kind: ErrorKind::ReportBadQuoteStatus(isv_enclave_quote_status, None),
                        cause: Some("Just joking, I'm rejecting all missing software mitigations".into()),
                    }),
                _ => Err(Error{
                        error_kind: ErrorKind::ReportBadQuoteStatus(isv_enclave_quote_status, None),
                        cause: None,
                    })
            }
        }
    }

    struct IgnoreSwMitigationNeeded;

    impl IgnoreSwMitigationNeeded {
        pub fn new() -> IgnoreSwMitigationNeeded {
            IgnoreSwMitigationNeeded {}
        }
    }

    impl Platform for IgnoreSwMitigationNeeded {
        fn verify(&self, _for_self: bool, _nonce: &Option<String>, isv_enclave_quote_status: QuoteStatus, _advisories: &Vec<IasAdvisoryId>) -> Result<(), Error> {
            match isv_enclave_quote_status {
                QuoteStatus::Ok | QuoteStatus::SwHardeningNeeded => Ok(()),
                _ => {
                    Err(Error::enclave_certificate(ErrorKind::ReportBadQuoteStatus(isv_enclave_quote_status, None), None::<Error>))
                }
            }
        }
    }

    // This is a report from IAS obtained using `sdkms-cli node attest`.
    #[cfg(feature="mbedtls")]
    const TEST_REPORT_BODY: &'static str = include_str!("../tests/data/test_report_body");

    // This is the IAS-issued signature on TEST_REPORT_BODY.
    #[cfg(feature="mbedtls")]
    const TEST_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/test_report_sig");

    // This is a report from IAS obtained using `sdkms-cli node attest` with a quote status of
    // INVALID_SIGNATURE. The backend was modified to corrupt byte 112 of the QE quote output
    // (first byte of mrenclave) in the SGX attester.
    #[cfg(feature="mbedtls")]
    const _INVALID_SIGNATURE_REPORT_BODY: &'static str = include_str!("../tests/data/invalid_signature_report_body");

    // This is the IAS-issued signature on INVALID_SIGNATURE_REPORT_BODY.
    #[cfg(feature="mbedtls")]
    const _INVALID_SIGNATURE_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/invalid_signature_report_sig");

    // This is the IAS report signing certificate.
    #[cfg(feature="mbedtls")]
    static TEST_REPORT_SIGNING_CERT: Lazy<Vec<u8>> = Lazy::new(|| {
        pem::pem_to_der(include_str!("../tests/data/test_report_signing_cert"),
                   Some(PEM_CERTIFICATE)).unwrap()
    });

    // This is a test_ca certificate with the above test report embedded.
    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    static TEST_ENCLAVE_CERT: Lazy<Vec<u8>> = Lazy::new(|| {
        pem::pem_to_der(include_str!("../tests/data/test_enclave_cert"),
                   Some(PEM_CERTIFICATE)).unwrap()
    });

    // This is a test_ca certificate with the INVALID_SIGNATURE report embedded
    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    static INVALID_SIGNATURE_ENCLAVE_CERT: Lazy<Vec<u8>> = Lazy::new(|| {
        pem::pem_to_der(include_str!("../tests/data/invalid_signature_enclave_cert"),
                    Some(PEM_CERTIFICATE)).unwrap()
    });

    // This is a test_ca certificate with an IAS v2 report embedded
    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    static WRONG_VERSION_ENCLAVE_CERT: Lazy<Vec<u8>> = Lazy::new(|| {
        pem::pem_to_der(include_str!("../tests/data/wrong_version_enclave_cert"),
                   Some(PEM_CERTIFICATE)).unwrap()
    });

    #[cfg(feature="mbedtls")]
    static TEST_REPORT_EXT: Lazy<AttestationEmbeddedIasReport<'static, 'static, 'static, Unverified>> = Lazy::new(|| {
        sgx_pkix::attestation::AttestationEmbeddedIasReport {
            http_body: Cow::Borrowed(TEST_REPORT_BODY.as_bytes()),
            report_sig: Cow::Borrowed(TEST_REPORT_SIG),
            certificates: vec![TEST_REPORT_SIGNING_CERT.as_slice().into()],
        }.into()
    });

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_success() {
        TEST_REPORT_EXT.clone().verify::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT]).unwrap();
    }

    macro_rules! assert_match {
        ($expr:expr, $pat:pat) => {
            assert!(if let $pat = $expr { true } else { false },
                "the value of `{}' should match the pattern `{}', but is `{:?}'", stringify!($expr), stringify!($pat), $expr)
        }
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_missing_cert() {
        let mut report = TEST_REPORT_EXT.clone();
        report.report.certificates = vec![];
        let result = report.verify::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportNoCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_cert() {
        let mut report = TEST_REPORT_EXT.clone();
        report.report.certificates = vec![vec![0x30, 0x00].into()];
        let result = report.verify::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportInvalidCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_wrong_cert() {
        let mut cert = GenericCertificate::from_der(TEST_REPORT_SIGNING_CERT.as_slice()).unwrap();
        cert.tbscert.spki.value.to_mut()[0] ^= 0x80;
        let result = TEST_REPORT_EXT.clone().verify::<Mbedtls>(&[&cert.to_der()]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_ca_cert() {
        let result = TEST_REPORT_EXT.clone().verify::<Mbedtls>(&[&vec![0x30, 0x00]]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_no_ca_cert() {
        let result = TEST_REPORT_EXT.clone().verify::<Mbedtls>(&[]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::CaNotConfigured, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_signature1() {
        // Signature corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.report.report_sig.to_mut()[0] ^= 0x80;
        let result = report.verify::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_signature2() {
        // Message (report JSON) corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.report.http_body.to_mut()[0] ^= 0x80;
        let result = report.verify::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT]).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[test]
    fn verify_report_status_bad_report_version_test() {
        let report = VerifyAttestationEvidenceResponse::<Unverified>::fake(1, None);

        let result = report.verify(&IgnoreSwMitigationNeeded::new()).map(|_| ()).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportBadVersion{ actual: 1 },
                          cause: _,
                      });
    }

    #[test]
    fn verify_report_sw_hardening_status_not_mitigated_test() {
        let report = VerifyAttestationEvidenceResponse::<Unverified>::fake(4, None);
        assert_match!(report.clone().verify(&NoSwMitigationInPlace::new()).as_ref().map(|_| ()).unwrap_err(),
                        Error {
                          error_kind: ErrorKind::ReportBadQuoteStatus(QuoteStatus::SwHardeningNeeded, _),
                          cause: _,
                      });
        assert!(report.verify(&IgnoreSwMitigationNeeded::new()).is_ok());
    }

    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    #[test]
    fn verify_peer_success() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(TEST_ENCLAVE_CERT.as_slice()).unwrap();
        assert_eq!(verify_epid_cert_embedded_attestation::<Mbedtls, _>(&ca_certs, &cert, &IgnoreSwMitigationNeeded::new()).unwrap(),
            EnclaveIdentity {
                mrenclave: vec![84, 7, 136, 241, 61, 74, 186, 244, 61, 186, 244, 63, 77, 70, 128, 217,
                                38, 75, 168, 32, 172, 162, 70, 138, 135, 115, 74, 133, 78, 30, 198, 253],
                mrsigner: vec![138, 17, 127, 251, 136, 251, 103, 211, 223, 231, 174, 57, 69, 173, 52, 191,
                               184, 198, 186, 109, 184, 15, 244, 171, 189, 188, 222, 59, 117, 137, 169, 131],
                isvprodid: 0,
                isvsvn: 0,
                attributes: Attributes {
                    flags: AttributesFlags::INIT | AttributesFlags::DEBUG | AttributesFlags::MODE64BIT,
                    xfrm: 7
                },
                miscselect: Miscselect::default(),
            }
        );
    }

    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    #[test]
    fn verify_peer_bad_signature() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let mut bad_cert = TEST_ENCLAVE_CERT.clone();
        // This is the first byte of the report signature. Index is computed as offset to IasReport
        // extension plus offset within IasReport extension.
        assert_eq!(bad_cert[494 + 934], 0x95);
        bad_cert[494 + 934] ^= 0x80;
        let bad_cert = GenericCertificate::from_der(&bad_cert).unwrap();
        let result = verify_epid_cert_embedded_attestation::<Mbedtls, _>(&ca_certs, &bad_cert, &IgnoreSwMitigationNeeded::new()).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    #[test]
    fn verify_peer_bad_reportdata() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let mut bad_cert = TEST_ENCLAVE_CERT.clone();
        // This is the MSB of the modulus in SPKI
        assert_eq!(bad_cert[169], 0xbe);
        bad_cert[169] ^= 0x80;
        let bad_cert = GenericCertificate::from_der(&bad_cert).unwrap();
        let result = verify_epid_cert_embedded_attestation::<Mbedtls, _>(&ca_certs, &bad_cert, &IgnoreSwMitigationNeeded::new()).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadPayload, cause: _ });
    }

    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    #[test]
    fn verify_peer_bad_status() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(INVALID_SIGNATURE_ENCLAVE_CERT.as_slice()).unwrap();
        let result = verify_epid_cert_embedded_attestation::<Mbedtls, _>(&ca_certs, &cert, &IgnoreSwMitigationNeeded::new()).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportBadQuoteStatus(QuoteStatus::SignatureInvalid, _),
                          cause: _,
                      });
    }

    #[cfg(all(target_env = "sgx", feature = "mbedtls"))]
    #[test]
    fn verify_peer_bad_version() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(WRONG_VERSION_ENCLAVE_CERT.as_slice()).unwrap();
        let result = verify_epid_cert_embedded_attestation::<Mbedtls, _>(&ca_certs, &cert, &IgnoreSwMitigationNeeded::new()).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportUnsupportedVersion { actual: IasVersion::V2, .. },
                          cause: _,
                      });
    }
}
