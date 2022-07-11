/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::api::{EnclaveQuoteBody, IasAdvisoryId, IasVersion, PlatformStatus, QuoteStatus, SUPPORTED_IAS_VERSIONS, VerifyAttestationEvidenceResponse};
use std::convert::TryInto;
use pkix::FromDer;
use pkix::x509::GenericCertificate;
use sgx_pkix::attestation::AttestationEmbeddedIasReport;
use sgx_isa::{Attributes, AttributesFlags, Miscselect};
#[cfg(target_env = "sgx")]
use sgx_isa::Report;
use std::fmt;
use std::result::Result;
use once_cell::sync::Lazy;

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
pub struct EnclavePeer {
    pub mrenclave: Vec<u8>,
    pub mrsigner: Vec<u8>,
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub attributes: Attributes,
    pub miscselect: Miscselect,
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

/*
TODO: Do we wish to publish this function?
/// Check that `cert` contains the `AttestationEmbeddedIasReport` X.509 extension and that the
/// report in that extension:
///
///  * has a valid signature from a trusted report signer
///  * reports a valid attestation
///  * had REPORTDATA containing the hash of `cert`'s SubjectPublicKeyInfo
///
/// If the checks pass, returns `Ok(EnclavePeer { ... })` with the enclave identity from the
/// validated report. If the checks do not pass, returns an error.
///
/// CAUTION: This routine does not verify the certificate signature nor the standard X.509
/// attributes. The caller is responsible for that.
#[cfg(all(test, feature = "mbedtls"))]
fn verify_epid_cert_embedded_attestation<C: Crypto>(ca_certificates: &[&[u8]], cert: &GenericCertificate) -> Result<EnclavePeer, Error> {
    let extn = cert.tbscert.get_extension(&oid::attestationEmbeddedIasReport)
        .ok_or_else(|| Error::enclave_certificate(ErrorKind::MissingIasReport, None::<Error>))?;

    // The extension is stored as a DER octetstring
    let ias_report = AttestationEmbeddedIasReport::from_der(&extn.value)
        .map_err(|e| Error::enclave_certificate(ErrorKind::ReportAsn1Parse, Some(e)))?;

    // The report must have a valid signature from a trusted report signer.
    verify_report::<C>(ca_certificates, &ias_report)?;

    // The report must have a valid status
    let report: VerifyAttestationEvidenceResponse = serde_json::from_slice(&ias_report.http_body)
        .map_err(|e| Error::enclave_certificate(ErrorKind::ReportJsonParse, Some(e)))?;
    let quote = verify_report_status(&report, &MITIGATED_SECURITY_ADVISORIES)?;

    // The SGX report data must contain the SPKI hash.
    //let mut expected_reportdata = vec![0; ::std::mem::size_of_val(&quote.reportdata)];
    let mut expected_reportdata = [0; crypto::SHA256_DIGEST_LEN];
    C::sha256(cert.tbscert.spki.as_ref(), &mut expected_reportdata)
        .map_err(|e| Error::enclave_certificate(ErrorKind::SpkiHashFailure, Some(e)))?;

    if expected_reportdata != &quote.reportdata[..] {
        return Err(Error::enclave_certificate(ErrorKind::ReportBadPayload, None::<Error>));
    }

    Ok(EnclavePeer {
        mrenclave: quote.mrenclave.to_vec(),
        mrsigner: quote.mrsigner.to_vec(),
        isvprodid: quote.isvprodid,
        isvsvn: quote.isvsvn,
        attributes: quote.attributes.clone(),
        miscselect: quote.miscselect,
    })
}
*/

/// Verify that `report` is correctly signed by a key that chains to one of the
/// trusted certificates in `ca_certificates`.
///
/// Does NOT verify the report contents.
pub fn verify_report<'a, C: Crypto>(ca_certificates: &[&[u8]], report: &AttestationEmbeddedIasReport<'a, 'a, 'a>) -> Result<(), Error> {
    // TODO: check the validity of the chain, and use the CA as the trust
    // anchor rather than the leaf. Chain verification outside the context
    // of TLS connection establishment does not seem to be exposed by
    // either the rust openssl or mbedtls bindings.

    let leaf_cert = match report.certificates.first() {
        None => return Err(Error::enclave_certificate(ErrorKind::ReportNoCertificate, None::<Error>)),
        Some(cert) => GenericCertificate::from_der(cert)
            .map_err(|e| Error::enclave_certificate(ErrorKind::ReportInvalidCertificate, Some(e)))?,
    };

    // This could be checked in the constructor, but we don't do that so that it's possible to
    // configure an empty cert list in no-attestation deployments.
    if ca_certificates.len() == 0 {
        return Err(Error::enclave_certificate(ErrorKind::CaNotConfigured, None::<Error>));
    }

    // Verify that the leaf cert appears in our list of trusted certificates
    if !ca_certificates.iter().map(GenericCertificate::from_der)
        .any(|c| match c {
            Ok(ref c) if c == &leaf_cert => true,
            _ => false
        }) {
        return Err(Error::enclave_certificate(ErrorKind::ReportUntrustedCertificate, None::<Error>));
    }

    C::rsa_sha256_verify(leaf_cert.tbscert.spki.as_ref(), &report.http_body, &report.report_sig)
        .map_err(|e| Error::enclave_certificate(ErrorKind::ReportBadSignature, Some(e)))?;

    Ok(())
}

pub fn verify_report_status(report: &VerifyAttestationEvidenceResponse, mitigated_advisory_ids: &Vec<IasAdvisoryId>) -> Result<EnclaveQuoteBody, Error> {
    fn error(report: &VerifyAttestationEvidenceResponse) -> Result<EnclaveQuoteBody, Error> {
        let pstatus = report.platform_info_blob.as_ref().map(|v| v.parse::<PlatformStatus>().map_err(|_| v.to_owned()) );
        return Err(Error::enclave_certificate(ErrorKind::ReportBadQuoteStatus(report.isv_enclave_quote_status, pstatus), None::<Error>));
    }

    // The report must be generated by the supported IAS version's
    match report.version.try_into() {
        Ok(actual) => {
            let supported = SUPPORTED_IAS_VERSIONS.to_vec();
            if !supported.contains(&actual) {
                return Err(Error::enclave_certificate(ErrorKind::ReportUnsupportedVersion { actual, supported }, None::<Error>));
            }
        },
        Err(_) => {
            return Err(Error::enclave_certificate(ErrorKind::ReportBadVersion { actual: report.version }, None::<Error>));
        }
    }

    let quote = EnclaveQuoteBody::try_copy_from(&report.isv_enclave_quote_body)
        .ok_or(Error::enclave_certificate(ErrorKind::ReportBadQuoteSize, None::<Error>))?;

    #[cfg(target_env = "sgx")]
    let for_self = {
        let report_self = Report::for_self();
        report_self.mrenclave == quote.mrenclave && report_self.mrsigner == quote.mrsigner
    };

    #[cfg(not(target_env = "sgx"))]
    let for_self = false;

    // The report must be for a valid quote.
    match (for_self, report.isv_enclave_quote_status) {
        (false, QuoteStatus::SwHardeningNeeded) => {
            /* We don't know how the enclave peer has been compiled. Our enclaves verify their own
             * attestations, so we can ignore `QuoteStatus::SwHardeningNeeded` here and rely on the
             * logic of enclave versions. It is of paramount importance that we only ignore
             * `QuoteStatus::SwHardeningNeeded` cases.
             * `QuoteStatus::ConfigurationAndSwHardeningNeeded` means that the platform itself
             * needs to be updated as well. (Advisory IDs on how to do this will be included in the
             * `report.advisory_ids`) Such attestations should *always* be rejected. */
        },
        (true, QuoteStatus::SwHardeningNeeded) => {
            /* Lets the enclave verify its own attestation. This enables us to inspect the compiler
             * used, and verify all software mitigations are in place. Quotes with status
             * `QuoteStatus::ConfigurationAndSwHardeningNeeded` represent insecure platforms and
             * should always be rejected. */
            debug!("IAS report's status is {:?}. Checking if security advisories in report are mitigated.", QuoteStatus::SwHardeningNeeded);
            if let Some(advisory_ids) = &report.advisory_ids {
                // check if advisories are mitigated
                let not_mitigated = advisory_ids
                    .iter()
                    .filter(|id| !mitigated_advisory_ids.contains(id) )
                    .collect::<Vec<_>>();
                if !not_mitigated.is_empty() {
                    debug!("Not mitiaged: {:?}", not_mitigated);
                    return error(report);
                }
            }
        },
        (_, QuoteStatus::Ok) => {}, // nothing to do
        _ => {
            return error(report);
        },
    }

    Ok(quote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
    use crate::api::{ENCLAVE_QUOTE_BODY_LEN, EnclaveQuoteBody, IasAdvisoryId, VerifyAttestationEvidenceResponse};
    #[cfg(feature="mbedtls")]
    use {
        super::crypto::Mbedtls,
        pkix::ToDer,
    };

    // This is a report from IAS obtained using `sdkms-cli node attest`.
    const TEST_REPORT_BODY: &'static str = include_str!("../tests/data/test_report_body");

    // This is the IAS-issued signature on TEST_REPORT_BODY.
    const TEST_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/test_report_sig");

    // This is a report from IAS obtained using `sdkms-cli node attest` with a quote status of
    // INVALID_SIGNATURE. The backend was modified to corrupt byte 112 of the QE quote output
    // (first byte of mrenclave) in the SGX attester.
    const _INVALID_SIGNATURE_REPORT_BODY: &'static str = include_str!("../tests/data/invalid_signature_report_body");

    // This is the IAS-issued signature on INVALID_SIGNATURE_REPORT_BODY.
    const _INVALID_SIGNATURE_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/invalid_signature_report_sig");

    lazy_static!{
        // This is the IAS report signing certificate.
        static ref TEST_REPORT_SIGNING_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/test_report_signing_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with the above test report embedded.
        static ref TEST_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/test_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with the INVALID_SIGNATURE report embedded
        static ref INVALID_SIGNATURE_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/invalid_signature_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with an IAS v2 report embedded
        static ref WRONG_VERSION_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/wrong_version_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        static ref TEST_REPORT_EXT: AttestationEmbeddedIasReport<'static, 'static, 'static> =
            AttestationEmbeddedIasReport {
                http_body: Cow::Borrowed(TEST_REPORT_BODY.as_bytes()),
                report_sig: Cow::Borrowed(TEST_REPORT_SIG),
                certificates: vec![TEST_REPORT_SIGNING_CERT.as_slice().into()],
            };
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_success() {
        verify_report::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT], &TEST_REPORT_EXT).unwrap();
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
        report.certificates = vec![];
        let result = verify_report::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportNoCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_cert() {
        let mut report = TEST_REPORT_EXT.clone();
        report.certificates = vec![vec![0x30, 0x00].into()];
        let result = verify_report::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportInvalidCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_wrong_cert() {
        let mut cert = GenericCertificate::from_der(TEST_REPORT_SIGNING_CERT.as_slice()).unwrap();
        cert.tbscert.spki.value.to_mut()[0] ^= 0x80;
        let result = verify_report::<Mbedtls>(&[&cert.to_der()], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_ca_cert() {
        let result = verify_report::<Mbedtls>(&[&vec![0x30, 0x00]], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_no_ca_cert() {
        let result = verify_report::<Mbedtls>(&[], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::CaNotConfigured, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_signature1() {
        // Signature corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.report_sig.to_mut()[0] ^= 0x80;
        let result = verify_report::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[test]
    #[cfg(feature="mbedtls")]
    fn verify_report_bad_signature2() {
        // Message (report JSON) corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.http_body.to_mut()[0] ^= 0x80;
        let result = verify_report::<Mbedtls>(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[test]
    fn verify_report_status_bad_report_version_test() {
        let mitigated = vec![IasAdvisoryId::from("INTEL-SA-00161")];
        let actual = Some(vec![]);
        let report = VerifyAttestationEvidenceResponse {
            id: "id".to_owned(),
            timestamp: "00:00:01".to_owned(),
            version: 1,
            isv_enclave_quote_status: QuoteStatus::SwHardeningNeeded,
            isv_enclave_quote_body: vec![],
            revocation_reason: None,
            pse_manifest_status: None,
            pse_manifest_hash: None,
            platform_info_blob: None,
            nonce: None,
            epid_pseudonym: None,
            advisory_url: None,
            advisory_ids: actual,
        };

        let result = verify_report_status(&report, &mitigated).map(|_| ()).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportBadVersion{ actual: 1 },
                          cause: _,
                      });
    }

    fn fake_quote_body() -> Vec<u8> {
        #[cfg(target_env = "sgx")]
        let (mrenclave, mrsigner) = {
            let report_self = Report::for_self();
            (report_self.mrenclave.clone(),
            report_self.mrsigner.clone())
        };

        #[cfg(not(target_env = "sgx"))]
        let (mrenclave, mrsigner) = ([0; 32], [0; 32]);

        let isv_enclave_quote_body = EnclaveQuoteBody {
            version: 4,
            signature_type: 0,
            gid: [0; 4],
            isvsvn_qe: 0,
            isvsvn_pce: 0,
            _reserved0: [0; 4],
            basename: [0; 32],

            cpusvn: [0; 16],
            miscselect: Miscselect::EXINFO,
            _reserved1: [0; 28],
            attributes: Attributes::default(),
            mrenclave,
            _reserved2: [0; 32],
            mrsigner,
            _reserved3: [0; 96],
            isvprodid:  0,
            isvsvn:     0,
            _reserved4: [0; 60],
            reportdata: [0; 64],
        };
        unsafe { std::mem::transmute::<_, [u8; ENCLAVE_QUOTE_BODY_LEN]>(isv_enclave_quote_body) }.into()
    }

    #[test]
    fn verify_report_sw_hardening_status_not_mitigated_test() {
        let test_data = vec![
            //(mitigated, actual)
            (vec![IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from("")])),
            (vec![IasAdvisoryId::from("")], Some(vec![IasAdvisoryId::from("INTEL-SA-00161")])),
            (vec![IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from(""), IasAdvisoryId::from("INTEL-SA-00161")])),
        ];
        for data in test_data.iter() {
            println!("test data: {:?}", data);
            let (mitigated, actual) = data;
            let report = VerifyAttestationEvidenceResponse {
                id: "id".to_owned(),
                timestamp: "00:00:01".to_owned(),
                version: 4,
                isv_enclave_quote_status: QuoteStatus::SwHardeningNeeded,
                isv_enclave_quote_body: fake_quote_body(),
                revocation_reason: None,
                pse_manifest_status: None,
                pse_manifest_hash: None,
                platform_info_blob: None,
                nonce: None,
                epid_pseudonym: None,
                advisory_url: None,
                advisory_ids: actual.clone(),
            };

            // The `verify_report_status` function only verifies the mitigated vulnerabilities when
            // it is verifying its own attestation
            let result = verify_report_status(&report, &mitigated);
            #[cfg(target_env = "sgx")]
            assert_match!(result.as_ref().map(|_| ()).unwrap_err(),
                          Error {
                              error_kind: ErrorKind::ReportBadQuoteStatus(QuoteStatus::SwHardeningNeeded, _),
                              cause: _,
                          });
            #[cfg(not(target_env = "sgx"))]
            assert!(result.is_ok())
        }
    }

    #[test]
    fn verify_report_sw_hardening_status_mitigated_test() {
        let test_data = vec![
            //(mitigated, actual)
            (vec![IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from("INTEL-sa-00161")])),
            (vec![IasAdvisoryId::from("INTEL-SA-00161")], None),
            (vec![], None),
            (vec![IasAdvisoryId::from(""), IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from("INTEL-SA-00161")])),
            (vec![IasAdvisoryId::from(""), IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from("INTEL-SA-00161")])),
            (vec![IasAdvisoryId::from(""), IasAdvisoryId::from("INTEL-SA-00161")], Some(vec![IasAdvisoryId::from("INTEL-SA-00161")])),
        ];
        for data in test_data.iter() {
            let (mitigated, actual) = data;
            let report = VerifyAttestationEvidenceResponse {
                id: "id".to_owned(),
                timestamp: "00:00:01".to_owned(),
                version: 4,
                isv_enclave_quote_status: QuoteStatus::SwHardeningNeeded,
                isv_enclave_quote_body: fake_quote_body(),
                revocation_reason: None,
                pse_manifest_status: None,
                pse_manifest_hash: None,
                platform_info_blob: None,
                nonce: None,
                epid_pseudonym: None,
                advisory_url: None,
                advisory_ids: actual.clone(),
            };

            assert!(verify_report_status(&report, &mitigated).is_ok());
        }
    }

    #[cfg(target_env = "sgx")]
    #[test]
    fn verify_peer_success() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(TEST_ENCLAVE_CERT.as_slice()).unwrap();
        assert_eq!(verify_epid_cert_embedded_attestation(&ca_certs, &cert).unwrap(),
            EnclavePeer {
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

    #[cfg(target_env = "sgx")]
    #[test]
    fn verify_peer_bad_signature() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let mut bad_cert = TEST_ENCLAVE_CERT.clone();
        // This is the first byte of the report signature. Index is computed as offset to IasReport
        // extension plus offset within IasReport extension.
        assert_eq!(bad_cert[494 + 934], 0x95);
        bad_cert[494 + 934] ^= 0x80;
        let bad_cert = GenericCertificate::from_der(&bad_cert).unwrap();
        let result = verify_epid_cert_embedded_attestation(&ca_certs, &bad_cert).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[cfg(target_env = "sgx")]
    #[test]
    fn verify_peer_bad_reportdata() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let mut bad_cert = TEST_ENCLAVE_CERT.clone();
        // This is the MSB of the modulus in SPKI
        assert_eq!(bad_cert[169], 0xbe);
        bad_cert[169] ^= 0x80;
        let bad_cert = GenericCertificate::from_der(&bad_cert).unwrap();
        let result = verify_epid_cert_embedded_attestation(&ca_certs, &bad_cert).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadPayload, cause: _ });
    }

    #[cfg(target_env = "sgx")]
    #[test]
    fn verify_peer_bad_status() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(INVALID_SIGNATURE_ENCLAVE_CERT.as_slice()).unwrap();
        let result = verify_epid_cert_embedded_attestation(&ca_certs, &cert).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportBadQuoteStatus(QuoteStatus::SignatureInvalid, _),
                          cause: _,
                      });
    }

    #[cfg(target_env = "sgx")]
    #[test]
    fn verify_peer_bad_version() {
        let ca_certs: Vec<&[u8]> = vec![&TEST_REPORT_SIGNING_CERT];
        let cert = GenericCertificate::from_der(WRONG_VERSION_ENCLAVE_CERT.as_slice()).unwrap();
        let result = verify_epid_cert_embedded_attestation(&ca_certs, &cert).unwrap_err();
        assert_match!(result,
                      Error {
                          error_kind: ErrorKind::ReportUnsupportedVersion { actual: IasVersion::V2, .. },
                          cause: _,
                      });
    }
}
