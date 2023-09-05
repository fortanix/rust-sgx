/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::borrow::Cow;

use mbedtls::rng::{Rdrand, Random};
use aws_nitro_enclaves_nsm_api::api::{Response, Request};
use aws_nitro_enclaves_nsm_api::driver;
use pkix::types::ObjectIdentifier;
use pkix::x509::DnsAltNames;
use pkix::{DerWrite, ToDer};
use serde_bytes::ByteBuf;
use vme_pkix::oid::{ATTESTATION_NITRO, ATTESTATION_NITRO_PCR0};

use crate::{CsrSigner, Error, get_csr_common_name};

type Result<T> = std::result::Result<T, Error>;

/// RAII wrapper for nsm_driver API:
pub struct NitroDriver(i32);

impl Drop for NitroDriver {
    fn drop(&mut self) {
        driver::nsm_exit(self.0)
    }
}

impl NitroDriver {
    pub fn init() -> Self {
        Self(driver::nsm_init())
    }
    fn request(&self, request: Request) -> Response {
        driver::nsm_process_request(self.0, request)
    }
    pub fn describe_pcr(&self, index: u16) -> Result<(bool, Vec<u8>)> {
        match self.request(Request::DescribePCR { index }) {
            Response::DescribePCR { lock, data } => Ok((lock, data)),
            Response::Error(e) => Err(Error::NsmDriver(format!("describe pcr{}: {:?}", index, e))),
            _ => Err(Error::UnexpectedNsmResponse("describe_pcr".into())),
        }
    }
    pub fn attestation(&self, user_data: &[u8], nonce: &[u8], public_key: Option<&[u8]>) -> Result<Vec<u8>> {
        let user_data = ByteBuf::from(user_data.to_vec());
        let nonce = ByteBuf::from(nonce);

        let request = Request::Attestation {
            public_key: public_key.map(ByteBuf::from),
            user_data: Some(user_data),
            nonce: Some(nonce),
        };
        match self.request(request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(e) => Err(Error::NsmDriver(format!("attestation {:?}", e))),
            _ => Err(Error::UnexpectedNsmResponse("attestation".into())),
        }
    }
}

pub(crate) fn get_remote_attestation_parameters(
    signer: &mut dyn CsrSigner,
    _url: &str,
    common_name: &str,
    user_data: &[u8;64],
    alt_names: Option<Vec<Cow<str>>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, String)> {
    let attributes = get_nitro_attestation(user_data)?;

    let extensions = alt_names.and_then(|names| {
        Some(vec![(pkix::oid::subjectAltName.clone(), false, pkix::yasna::construct_der(|w| DnsAltNames { names }.write(w)).into())])
    });

    let csr_pem = get_csr_common_name(signer, &common_name, attributes, &extensions)?;

    Ok((None, None, csr_pem))
}

/// This PCR0 provided by environment variable is only read for debug enclaves;
/// which are insecure by default. Since the Nitro hardware does not have any
/// enclave identity readable, we allow identity to be specified on the CLI;
/// but the "debug" nature of the attestation allows clients to be skeptical of
/// that identity if they choose.
fn pcr0_from_env_insecure() -> Result<Vec<u8>> {
    let value = std::env::var("DEBUG_PCR0")
        .map_err(|_| Error::AttestationCertInternal("Missing 'DEBUG_PCR0' inside debug enclave.".into()))?;
    Ok(hex::decode(value)
        .map_err(|_| Error::AttestationCertInternal("Value of DEBUG_PCR0 is invalid hex.".into()))?)
}

/// Retrieve a Nitro attestation with the given user_data and return it as an
/// extension or list of extensions ready for inclusion into a CSR.
pub(crate) fn get_nitro_attestation(user_data: &[u8;64]) -> Result<Vec<(ObjectIdentifier, Vec<Vec<u8>>)>> {
    const NONCE_SIZE: usize = 16;

    let mut nonce = [0; NONCE_SIZE];
    Rdrand.random(&mut nonce[..]).map_err(|e| Error::NonceGeneration(Box::new(e)))?;

    let nsm = NitroDriver::init();

    let buffer = nsm.attestation(user_data, &nonce, None)?;
    let (locked, pcr0) = nsm.describe_pcr(0)?;
    if !locked {
        return Err(Error::NsmDriver("Nitro PCR0 should be locked.".into()))
    }
    let mut output = Vec::new();
    output.push((ATTESTATION_NITRO.clone(), vec![buffer.to_vec().to_der()]));

    // If all PCR0 values are zero, this is a debug enclave.
    if pcr0.iter().all(|x| *x == 0) {
        // To identify builds, include PCR0 from env variable; this is untrusted.
        output.push((ATTESTATION_NITRO_PCR0.clone(), vec![pcr0_from_env_insecure()?]));
    }

    Ok(output)
}
