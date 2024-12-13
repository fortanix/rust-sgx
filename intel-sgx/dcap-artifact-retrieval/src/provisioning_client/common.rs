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

pub struct PckCertsApiNotSupported;

impl<'inp> PckCertsService<'inp> for PckCertsApiNotSupported {
    fn build_input(
        &'inp self,
        enc_ppid: &'inp EncPpid,
        pce_id: PceId,
    ) -> <Self as ProvisioningServiceApi<'inp>>::Input {
        PckCertsIn {
            enc_ppid,
            pce_id,
            api_key: &None,
            api_version: PcsVersion::V3, // does not matter, this API is not supported!
        }
    }
}

impl<'inp> ProvisioningServiceApi<'inp> for PckCertsApiNotSupported {
    type Input = PckCertsIn<'inp>;
    type Output = PckCerts;

    fn build_request(
        &self,
        _input: &Self::Input,
    ) -> Result<(String, Vec<(String, String)>), Error> {
        Err(Error::RequestNotSupported)
    }

    fn validate_response(&self, _status_code: StatusCode) -> Result<(), Error> {
        Err(Error::RequestNotSupported)
    }

    fn parse_response(
        &self,
        _response_body: String,
        _response_headers: Vec<(String, String)>,
        _api_version: PcsVersion,
    ) -> Result<Self::Output, Error> {
        Err(Error::RequestNotSupported)
    }
}

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
