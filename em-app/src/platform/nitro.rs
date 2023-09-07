/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use crate::platform::get_extensions_from_alt_names;
use crate::{common_name_to_subject, get_csr, CsrSigner, Error};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use mbedtls::rng::{Random, Rdrand};
use pkix::types::{Name, ObjectIdentifier};
use pkix::ToDer;
use std::borrow::Cow;
use vme_pkix::oid::ATTESTATION_NITRO;

type Result<T> = std::result::Result<T, Error>;

pub(crate) fn get_remote_attestation_parameters_subject(
    signer: &mut dyn CsrSigner,
    _url: &str,
    subject: &Name,
    user_data: &[u8;64],
    alt_names: Option<Vec<Cow<str>>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, String)> {
    let attributes = get_nitro_attestation(user_data)?;

    let extensions = get_extensions_from_alt_names(alt_names);

    let csr_pem = get_csr(signer, &subject, attributes, &extensions)?;

    Ok((None, None, csr_pem))
}

// Kept in place for legacy purposes
#[allow(dead_code)]
pub(crate) fn get_remote_attestation_parameters(
    signer: &mut dyn CsrSigner,
    url: &str,
    common_name: &str,
    user_data: &[u8;64],
    alt_names: Option<Vec<Cow<str>>>,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, String)> {
    let subject = common_name_to_subject(common_name);
    get_remote_attestation_parameters_subject(signer, url, &subject, user_data, alt_names)
}

pub(crate) fn get_nitro_attestation(user_data: &[u8;64]) -> Result<Vec<(ObjectIdentifier, Vec<Vec<u8>>)>> {
    const NONCE_SIZE: usize = 16;

    let mut nonce = [0; NONCE_SIZE];
    Rdrand.random(&mut nonce[..]).map_err(|e| Error::NonceGeneration(Box::new(e)))?;

    let nsm_fd = driver::nsm_init();

    let user_data = serde_bytes::ByteBuf::from(user_data.to_vec());
    let nonce = serde_bytes::ByteBuf::from(nonce);

    let request = Request::Attestation {
        public_key: None,
        user_data: Some(user_data),
        nonce: Some(nonce),
    };

    let response = driver::nsm_process_request(nsm_fd, request);

    driver::nsm_exit(nsm_fd);

    let buffer = match response {
        Response::Attestation { document: attestation_doc } => Ok(attestation_doc),
        Response::Error(e) => Err(Error::NsmDriver(format!("Failed getting attestation from nsm_driver, error: {:?}", e))),
        unknown => Err(Error::UnexpectedNsmResponse(format!("Unknown response from nsm_driver: {:?}", unknown))),
    }?;

    Ok(vec![(ATTESTATION_NITRO.clone(), vec![buffer.to_vec().to_der()])])
}
