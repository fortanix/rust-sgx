/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::borrow::Cow;
use pkix::types::{ObjectIdentifier};
use pkix::x509::DnsAltNames;
use pkix::{DerWrite, ToDer};

#[cfg(not(feature = "fake_attestation"))]
use mbedtls::rng::{Rdrand, Random};
#[cfg(not(feature = "fake_attestation"))]
use nsm_io::{Response};

use crate::{CsrSigner, Error, get_csr_common_name};

type Result<T> = std::result::Result<T, Error>;

// This will be moved to a pkix crate and a different OID assigned
lazy_static! {
    pub static ref ATTESTATION_NITRO: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 6].into();
}

pub fn get_remote_attestation_parameters(
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

#[cfg(not(feature = "fake_attestation"))]
pub fn get_nitro_attestation(user_data: &[u8;64]) -> Result<Vec<(ObjectIdentifier, Vec<Vec<u8>>)>> {
    const NONCE_SIZE: usize = 16;

    let mut nonce = [0; NONCE_SIZE];
    Rdrand.random(&mut nonce[..]).map_err(|e| Error::NonceGeneration(Box::new(e)))?;

    let nsm_fd = nsm_driver::nsm_init();
    
    let user_data = serde_bytes::ByteBuf::from(user_data.to_vec());
    let nonce = serde_bytes::ByteBuf::from(nonce);

    let request = nsm_io::Request::Attestation {
        public_key: None,
        user_data: Some(user_data),
        nonce: Some(nonce),
    };

    let response = nsm_driver::nsm_process_request(nsm_fd, request);

    nsm_driver::nsm_exit(nsm_fd);

    let buffer = match response {
        Response::Attestation { document: attestation_doc } => Ok(attestation_doc),
        Response::Error(e) => Err(Error::NsmDriver(format!("Failed getting attestation from nsm_driver, error: {:?}", e))),
        unknown => Err(Error::UnexpectedNsmResponse(format!("Unknown response from nsm_driver: {:?}", unknown))),
    }?;

    Ok(vec![(ATTESTATION_NITRO.clone(), vec![buffer.to_vec().to_der()])])
}

#[cfg(feature = "fake_attestation")]
pub fn get_nitro_attestation(_user_data: &[u8;64]) -> Result<Vec<(ObjectIdentifier, Vec<Vec<u8>>)>> {
    let buffer = include_bytes!("../../tests/expired_attestation.bin");
    Ok(vec![(ATTESTATION_NITRO.clone(), vec![buffer.to_vec().to_der()])])
}
