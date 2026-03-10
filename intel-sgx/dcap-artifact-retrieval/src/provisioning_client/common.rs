/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use pcs::{EncPpid, PceId, PckCerts};
use percent_encoding::percent_decode;
use pkix::pem::PemBlock;

use super::{PckCertsIn, PckCertsService, PcsVersion, ProvisioningServiceApi, StatusCode};
use crate::Error;

pub const PCK_CERTIFICATE_ISSUER_CHAIN_HEADER: &'static str = "SGX-PCK-Certificate-Issuer-Chain";
pub const PCK_CRL_ISSUER_CHAIN_HEADER: &'static str = "SGX-PCK-CRL-Issuer-Chain";
pub const TCB_INFO_ISSUER_CHAIN_HEADER_V3: &'static str = "SGX-TCB-Info-Issuer-Chain";
pub const TCB_INFO_ISSUER_CHAIN_HEADER_V4: &'static str = "TCB-Info-Issuer-Chain";
pub const ENCLAVE_ID_ISSUER_CHAIN_HEADER: &'static str = "SGX-Enclave-Identity-Issuer-Chain";
pub const TCB_EVALUATION_DATA_NUMBERS_ISSUER_CHAIN: &'static str = "TCB-Evaluation-Data-Numbers-Issuer-Chain";

/// Returns the certificate chain starting from the leaf CA.
pub fn parse_issuer_header(
    headers: &Vec<(String, String)>,
    header: &'static str,
) -> Result<Vec<String>, Error> {
    let cert_chain = headers
        .iter()
        .find_map(|(key, value)| {
            if key.to_lowercase() == header.to_lowercase() {
                Some(value)
            } else {
                None
            }
        })
        .ok_or(Error::HeaderMissing(header))?;

    let cert_chain = percent_decode(cert_chain.as_bytes())
        .decode_utf8()
        .map_err(|e| Error::HeaderDecodeError(e))?;

    let mut chain: Vec<String> = vec![];
    for cert in PemBlock::new(cert_chain.as_bytes()) {
        let cert = String::from_utf8(cert.to_vec())
            .map_err(|_| Error::CertificateParseError("Cert could not be decoded into utf8"))?;

        chain.push(cert);
    }
    Ok(chain)
}
