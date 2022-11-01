/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::verifier::{Error as VerifierError, ErrorKind};
use mbedtls;
use mbedtls::alloc::List as MbedtlsList;
use mbedtls::hash::{Md, Type};
use mbedtls::pk::Pk;
use mbedtls::x509::Certificate;
use mbedtls::Error;
use pkix::types::DerSequence;

use super::{private::Crypto, SHA256_DIGEST_LEN};

pub struct Mbedtls;

impl Crypto for Mbedtls {
    type Error = Error;

    fn sha256(message: &[u8], digest: &mut [u8; SHA256_DIGEST_LEN]) -> ::std::result::Result<(), Self::Error> {
        Md::hash(Type::Sha256, &message, digest)?;
        Ok(())
    }

    fn rsa_sha256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> ::std::result::Result<(), Self::Error> {
        let mut pk = Pk::from_public_key(public_key)?;

        let mut hash = vec![0; SHA256_DIGEST_LEN];
        Md::hash(Type::Sha256, &message, &mut hash)?;

        pk.verify(Type::Sha256, &hash, &signature)?;

        Ok(())
    }

    fn x509_verify_chain(
        cert_chain: &Vec<DerSequence>,
        ca_certs: &Vec<DerSequence>,
    ) -> ::std::result::Result<(), VerifierError> {
        let cert_chain = der_to_mbedtls_cert_list(cert_chain)
            .map_err(|e| VerifierError::enclave_certificate(ErrorKind::ReportInvalidCertificate, Some(e)))?;
        let ca_certs = der_to_mbedtls_cert_list(ca_certs)
            .map_err(|e| VerifierError::enclave_certificate(ErrorKind::InvalidCaCertificate, Some(e)))?;
        Certificate::verify(&cert_chain, &ca_certs, None)
            .map_err(|e| VerifierError::enclave_certificate(ErrorKind::ReportUntrustedCertificate, Some(e)))?;
        Ok(())
    }
}

fn der_to_mbedtls_cert_list(certificates: &Vec<DerSequence>) -> Result<MbedtlsList<Certificate>, Error> {
    let mut list = MbedtlsList::new();
    for c in certificates {
        list.push(Certificate::from_der(c.value.as_ref())?);
    }
    Ok(list)
}
