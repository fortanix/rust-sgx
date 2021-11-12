/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::x509::GenericCertificate;
use pkix::types::HasOid;
use pkix::FromDer;
use sgx_isa::Report;

use super::attestation::{AttestationInlineSgxLocal, reconstruct_sgx_report};
use super::{Error, Result};

pub fn cert_to_sgx_report(cert: &GenericCertificate) -> Result<Report> {
    let attestation = cert.tbscert.get_extension(AttestationInlineSgxLocal::oid()).ok_or(Error::MissingAttestation)?;
    let attestation = AttestationInlineSgxLocal::from_der(&attestation.value).map_err(|_| Error::InvalidAttestation)?;
    reconstruct_sgx_report(&cert.tbscert.subject, &attestation)
}
