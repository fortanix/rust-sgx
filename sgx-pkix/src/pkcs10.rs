/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::pkcs10::DerCertificationRequest;
use sgx_isa::Report;

use super::attestation::{AttestationInlineSgxLocal, reconstruct_sgx_report};
use super::{Error, Result};

pub fn csr_to_sgx_report(csr: &DerCertificationRequest) -> Result<Report> {
    let attestation: AttestationInlineSgxLocal = csr.get_singular_attribute().ok_or(Error::MissingAttestation)?;
    reconstruct_sgx_report(&csr.reqinfo.subject, &attestation)
}
