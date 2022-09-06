/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::api::{QuoteStatus, PlatformStatus};
use pkix::FromDer;
use pkix::x509::GenericCertificate;
use sgx_pkix::attestation::AttestationEmbeddedIasReport;
use sgx_isa::{AttributesFlags, Miscselect};
use std::fmt;
use std::result::Result;

pub mod crypto;
pub use self::crypto::private::Crypto;

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
    ReportBadVersion { actual: u64, expected: u64 },
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
            ReportBadVersion { actual, expected } => f.write_fmt(format_args!("report version is {}, expected {}", actual, expected)),
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

#[cfg(all(test, feature = "mbedtls"))]
mod tests {
    use super::*;
    use std::borrow::{Cow};
    use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
    use pkix::ToDer;

    // This is a report from IAS obtained using `sdkms-cli node attest`.
    const TEST_REPORT_BODY: &'static str = include_str!("../tests/data/reports/test_report_body");

    // This is the IAS-issued signature on TEST_REPORT_BODY.
    const TEST_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/reports/test_report_sig");

    // This is a report from IAS obtained using `sdkms-cli node attest` with a quote status of
    // INVALID_SIGNATURE. The backend was modified to corrupt byte 112 of the QE quote output
    // (first byte of mrenclave) in the SGX attester.
    const _INVALID_SIGNATURE_REPORT_BODY: &'static str = include_str!("../tests/data/reports/invalid_signature_report_body");

    // This is the IAS-issued signature on INVALID_SIGNATURE_REPORT_BODY.
    const _INVALID_SIGNATURE_REPORT_SIG: &'static [u8] = include_bytes!("../tests/data/reports/invalid_signature_report_sig");

    #[allow(non_upper_case_globals)]
    const verify_report: for<'a> fn(ca_certificates: &[&[u8]], report: &AttestationEmbeddedIasReport<'a, 'a, 'a>) -> Result<(), Error>
        = super::verify_report::<super::crypto::Mbedtls>;

    lazy_static::lazy_static!{
        // This is the IAS report signing certificate.
        static ref TEST_REPORT_SIGNING_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/reports/test_report_signing_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with the above test report embedded.
        static ref TEST_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/reports/test_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with the INVALID_SIGNATURE report embedded
        static ref INVALID_SIGNATURE_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/reports/invalid_signature_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        // This is a test_ca certificate with an IAS v2 report embedded
        static ref WRONG_VERSION_ENCLAVE_CERT: Vec<u8> =
            pem_to_der(include_str!("../tests/data/reports/wrong_version_enclave_cert"),
                       Some(PEM_CERTIFICATE)).unwrap();

        static ref TEST_REPORT_EXT: AttestationEmbeddedIasReport<'static, 'static, 'static> =
            AttestationEmbeddedIasReport {
                http_body: Cow::Borrowed(TEST_REPORT_BODY.as_bytes()),
                report_sig: Cow::Borrowed(TEST_REPORT_SIG),
                certificates: vec![TEST_REPORT_SIGNING_CERT.as_slice().into()],
            };
    }

    #[test]
    fn verify_report_success() {
        verify_report(&[&TEST_REPORT_SIGNING_CERT], &TEST_REPORT_EXT).unwrap();
    }

    macro_rules! assert_match {
        ($expr:expr, $pat:pat) => {
            assert!(if let $pat = $expr { true } else { false },
                "the value of `{}' should match the pattern `{}', but is `{:?}'", stringify!($expr), stringify!($pat), $expr)
        }
    }

    #[test]
    fn verify_report_missing_cert() {
        let mut report = TEST_REPORT_EXT.clone();
        report.certificates = vec![];
        let result = verify_report(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportNoCertificate, cause: _ });
    }

    #[test]
    fn verify_report_bad_cert() {
        let mut report = TEST_REPORT_EXT.clone();
        report.certificates = vec![vec![0x30, 0x00].into()];
        let result = verify_report(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportInvalidCertificate, cause: _ });
    }

    #[test]
    fn verify_report_wrong_cert() {
        let mut cert = GenericCertificate::from_der(TEST_REPORT_SIGNING_CERT.as_slice()).unwrap();
        cert.tbscert.spki.value.to_mut()[0] ^= 0x80;
        let result = verify_report(&[&cert.to_der()], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    fn verify_report_bad_ca_cert() {
        let result = verify_report(&[&vec![0x30, 0x00]], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportUntrustedCertificate, cause: _ });
    }

    #[test]
    fn verify_report_no_ca_cert() {
        let result = verify_report(&[], &TEST_REPORT_EXT).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::CaNotConfigured, cause: _ });
    }

    #[test]
    fn verify_report_bad_signature1() {
        // Signature corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.report_sig.to_mut()[0] ^= 0x80;
        let result = verify_report(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }

    #[test]
    fn verify_report_bad_signature2() {
        // Message (report JSON) corrupted
        let mut report = TEST_REPORT_EXT.clone();
        report.http_body.to_mut()[0] ^= 0x80;
        let result = verify_report(&[&TEST_REPORT_SIGNING_CERT], &report).unwrap_err();
        assert_match!(result, Error { error_kind: ErrorKind::ReportBadSignature, cause: _ });
    }
}
