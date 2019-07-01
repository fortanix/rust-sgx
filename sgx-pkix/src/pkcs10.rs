/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::pkcs10::DerCertificationRequest;
use pkix::types::TaggedDerValue;
use sgx_isa::Report;

use super::attestation::{AttestationInlineSgxLocal, attributes_from_bytes, miscselect_from_bytes, isvprodid_from_bytes,
                         isvsvn_from_bytes};
use super::oid;
use super::{Error, Result};

fn bytes(src: &TaggedDerValue) -> Result<&[u8]> {
    src.as_bytes().ok_or(Error::InvalidValue)
}

fn assign_slice(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != src.len() {
        return Err(Error::InvalidLength)
    }
    dst.copy_from_slice(src);
    Ok(())
}

pub fn csr_to_sgx_report(csr: &DerCertificationRequest) -> Result<Report> {
    let subject = &csr.reqinfo.subject;
    let cpusvn = subject.get(&oid::sgxCpusvn).ok_or(Error::MissingCpusvn)?;
    let miscselect = subject.get(&oid::sgxMiscselect).ok_or(Error::MissingMiscselect)?;
    let attributes = subject.get(&oid::sgxAttributes).ok_or(Error::MissingAttributes)?;
    let mrenclave = subject.get(&oid::sgxMrenclave).ok_or(Error::MissingMrenclave)?;
    let mrsigner = subject.get(&oid::sgxMrsigner).ok_or(Error::MissingMrsigner)?;
    let isvprodid = subject.get(&oid::sgxIsvprodid).ok_or(Error::MissingIsvprodid)?;
    let isvsvn = subject.get(&oid::sgxIsvsvn).ok_or(Error::MissingIsvsvn)?;
    let reportdata = subject.get(&oid::sgxReportdata).ok_or(Error::MissingReportdata)?;

    let attestation: AttestationInlineSgxLocal = csr.get_singular_attribute().ok_or(Error::MissingAttestation)?;

    let mut report = Report::default();
    bytes(cpusvn).and_then(|b| assign_slice(&mut report.cpusvn, b)).map_err(|_| Error::InvalidCpusvn)?;
    bytes(mrenclave).and_then(|b| assign_slice(&mut report.mrenclave, b)).map_err(|_| Error::InvalidMrenclave)?;
    bytes(mrsigner).and_then(|b| assign_slice(&mut report.mrsigner, b)).map_err(|_| Error::InvalidMrsigner)?;
    bytes(reportdata).and_then(|b| assign_slice(&mut report.reportdata, b)).map_err(|_| Error::InvalidReportdata)?;

    report.miscselect = bytes(miscselect).and_then(|b| miscselect_from_bytes(b)).map_err(|_| Error::InvalidMiscselect)?;
    report.attributes = bytes(attributes).and_then(|b| attributes_from_bytes(b)).map_err(|_| Error::InvalidAttributes)?;

    report.isvprodid = bytes(isvprodid).and_then(|b| isvprodid_from_bytes(b))?;
    report.isvsvn = bytes(isvsvn).and_then(|b| isvsvn_from_bytes(b))?;

    assign_slice(&mut report.keyid, &attestation.keyid).map_err(|_| Error::InvalidKeyid)?;
    assign_slice(&mut report.mac, &attestation.mac).map_err(|_| Error::InvalidMac)?;

    Ok(report)
}
