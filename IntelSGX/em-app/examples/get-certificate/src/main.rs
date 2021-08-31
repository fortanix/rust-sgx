/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* Copyright (c) Fortanix, Inc. */

/* Usage example for certificate library. This obtains an EM signed certificate if everything is configured correctly.*/
extern crate mbedtls;
extern crate em_app;

use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;

use em_app::*;
use std::env;

fn main() -> Result<(), String> {
    // Running in SGX - need to manually enable backtrace so we get nice warnings - this should disappear in production environment
    env::set_var("RUST_BACKTRACE", "1");

    // Generate key - mbedtls::Pk has required trait implemented - customers may choose any other mechanism to create certificates
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001).unwrap();

    // This must be on localhost otherwise local attestation will not work
    let node_agent_url = "http://localhost:9092";
    
    // Call to library to fetch certificates
    match get_fortanix_em_certificate(node_agent_url, "localhost", &mut key) {
        Ok(result) =>  println!("{}", serde_json::to_string_pretty(&result.certificate_response).unwrap()),
        Err(e) => println!("Error: {}", e),
    }

    Ok(())
}
