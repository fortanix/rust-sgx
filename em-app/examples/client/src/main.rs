/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* Copyright (c) Fortanix, Inc. */

/* Simple client application using EM signed certificate. This will connect to a server enclave and communicate only if other party is validated.*/
extern crate mbedtls;
extern crate em_app;

use mbedtls::pk::Pk;

use em_app::*;
use std::env;

use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use pkix::pem::{pem_to_der, PEM_CERTIFICATE};

use std::io::{self, Write};
use std::net::TcpStream;

// Generated before compilation, will be embedded in enclave source code.
pub const SERVER_ADDR: &'static str = "localhost:21000";
pub const ZONE_CA_PEM: &'static str  = include_str!("../artifacts/zone_ca.crt");

fn main() -> Result<(), String> {
    // Running in SGX - need to manually enable backtrace so we get nice warnings - this should disappear in production environment
    env::set_var("RUST_BACKTRACE", "full");

    // Generate key - mbedtls::Pk has required trait implemented - customers may choose any other mechanism to create certificates
    let mut rng = FtxRng;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001).unwrap();

    // This must be on localhost otherwise local attestation will not work
    let node_agent_url = "http://localhost:9092";
    
    // Call to library to fetch certificates
    let result = get_fortanix_em_certificate(node_agent_url, "localhost", &mut key).map_err(|e| format!("Error: {}", e))?;
    println!("Application: obtained signed certificate from EM: {}", serde_json::to_string_pretty(&result.certificate_response).map_err(|e| format!("Failed decoding certificate response: {:?}", e))?);

    let zone_ca = Certificate::from_der(&pem_to_der(&ZONE_CA_PEM, Some(PEM_CERTIFICATE)).unwrap())
                                       .map_err(|e| format!("mbedtls failed to parse DER file: {:?}", e))?;

    let app_cert = Certificate::from_der(&pem_to_der(&result.certificate_response.certificate.unwrap(), Some(PEM_CERTIFICATE)).unwrap())
                                       .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;
    
    run_client(app_cert, zone_ca, key).map_err(|e| format!("Error in client: {:?}", e))?;
    
    Ok(())
}

fn run_client(mut cert: Certificate, mut zone_ca: Certificate, mut key: Pk) -> Result<(), String> {
    let mut rng = FtxRng;

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(Some(&mut rng));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    // Client certificate use to authenticate on the server
    config.push_cert(&mut *cert, &mut key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    // CA that we accept from the server
    config.set_ca_list(Some(&mut *zone_ca), None);
    let mut ctx = Context::new(&config).map_err(|e| format!("TLS context creation failed: {:?}", e))?;

    // Establish connection
    let mut conn = TcpStream::connect(SERVER_ADDR).map_err(|e| format!("TCP connect error: {:?}", e))?;
    let mut session = ctx.establish(&mut conn, None).map_err(|e| format!("TLS Session error: {:?}", e))?;

    // Write a simple message
    session.write_all("Hello from client\n".as_bytes()).map_err(|e| format!("Message write fail: {:?}", e))?;

    // Output any data sent by the server
    let mut buffer: Vec<u8> = vec![];
    io::copy(&mut session, &mut buffer).map_err(|e| format!("read fail: {:?}", e))?;
    println!("Application: received data from server: {:?}.", String::from_utf8(buffer).map_err(|e| format!("Failed parsing server reply as utf-8: {:?}", e))?);

    // Example finished
    println!("Client finished");
    Ok(())
}
