/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
pub extern crate serde_derive;

use std::env;
use std::sync::Arc;
use std::collections::HashMap;

use b64_ct::{FromBase64};
use em_app::*;
use mbedtls::alloc::{List as MbedtlsList};
use mbedtls::pk::Pk;
use mbedtls::x509::{Certificate, Crl};
use sdkms::api_model::Blob;
use url::Url;

use em_app::utils::{CredentialsEncryption, get_runtime_configuration, get_sdkms_dataset, https_get, https_put, decrypt_buffer, encrypt_buffer};
use em_app::utils::models::{RuntimeAppConfig, ApplicationConfigConnectionDataset};

fn main() -> Result<(), String> {
    env::set_var("RUST_BACKTRACE", "full");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(format!("Usage: ftxsgx-runner {} app-config-id", args[0]));
    }

    // Generate key - mbedtls::Pk has required trait implemented - customers may choose any other mechanism to create certificates
    let mut rng = FtxRng;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001).unwrap();

    // This is always on localhost but the port might be different
    let node_agent_url = "http://localhost:9092";

    // This must be on localhost otherwise local attestation will not work
    let em_server = "ccm.fortanix.com";
    let em_port = 443;

    let em_ca_cert = Some(Arc::new(Certificate::from_pem_multiple(concat!(include_str!("../certs/em_ca_cert.pem"), "\0").as_bytes()).map_err(|e| format!("Invalid CA Cert for CCM: {:?}", e))?));
    let em_crl = None;
    let sdkms_ca_cert = em_ca_cert.clone();
    let sdkms_crl = None;

    let storage_ca = Some(Arc::new(Certificate::from_pem_multiple(concat!(include_str!("../certs/aws_s3.pem"), "\0").as_bytes()).map_err(|e| format!("Invalid CA Cert for CCM: {:?}", e))?));
    let storage_crl = None;
    
    let config_id = args[1].clone();

    let result = get_certificate(node_agent_url,"localhost", &mut key, None, Some(&config_id)).map_err(|e| format!("Error: {}", e))?;
    println!("\na. Public certificate is signed: \n{}", serde_json::to_string_pretty(&result.certificate_response).map_err(|e| format!("Failed decoding certificate response: {:?}", e))?);

    let mut cert_pem = result.certificate_response.certificate.ok_or("Missing certificate in response")?;
    cert_pem.push('\0');

    let app_cert = Arc::new(Certificate::from_pem_multiple(&cert_pem.as_bytes()).map_err(|e| format!("Parsing certificate failed: {:?}", e))?);
    let key = Arc::new(key);

    let config = get_runtime_configuration(em_server, em_port, app_cert.clone(), key.clone(), em_ca_cert, em_crl).map_err(|e| format!("Error in client: {:?}", e))?;
    println!("\nb. Application configuration: \n{}", serde_json::to_string_pretty(&config).map_err(|e| format!("Failed decoding response: {:?}", e))?);

    let (input, input_credentials) = get_credentials("input", &config, app_cert.clone(), key.clone(), sdkms_ca_cert.clone(), sdkms_crl.clone())?;
    println!("\nc.1. 'input' port dataset value from SDKMS: \n{}", serde_json::to_string_pretty(&input_credentials).unwrap());

    let (output, output_credentials) = get_credentials("output", &config, app_cert.clone(), key.clone(), sdkms_ca_cert.clone(), sdkms_crl.clone())?;
    println!("\nd.2. 'output' port dataset value from SDKMS: \n{}", serde_json::to_string_pretty(&output_credentials).unwrap());

    let query_string = input_credentials.query_string.from_base64().map_err(|e| format!("Failed decoding query string: {:?}", e))?;
    let query_string = &String::from_utf8(query_string).map_err(|e| format!("Query string is not utf-8: {:?}", e))?;

    let url = input.location.to_owned() + "?" + query_string;
    let url = Url::parse(&url).map_err(|e| format!("Failed parsing input url, error: {:?}", e))?;
    
    let body: Vec<u8> = https_get(url, storage_ca.clone(), storage_crl.clone())?;
    println!("\ne. Downloaded input.");
    
    let decrypted = decrypt_buffer(&body, &input_credentials.encryption)?;
    println!("\nf. Decrypted input.");

    let data = process(decrypted).map_err(|e| format!("Failed processing CSV file, error: {:?}", e))?;
    
    let encrypted = encrypt_buffer(&data.as_bytes(), &output_credentials.encryption)?;
    println!("\nh.Encrypted output: \n{}", get_ascii(&encrypted, false));

    let query_string = output_credentials.query_string.from_base64().map_err(|e| format!("Failed decoding query string: {:?}", e))?;
    let query_string = &String::from_utf8(query_string).map_err(|e| format!("Query string is not utf-8: {:?}", e))?;

    let url = output.location.to_owned() + "?" + query_string;
    let url = Url::parse(&url).map_err(|e| format!("Failed parsing input url, error: {:?}", e))?;
    https_put(url, encrypted, storage_ca.clone(), storage_crl.clone())?;

    println!("\ni. Upload finished at location: {}", output.location);
    Ok(())
}


pub fn get_credentials<'a>(port: &str,
                           config: &'a RuntimeAppConfig,
                           app_cert: Arc<MbedtlsList<Certificate>>,
                           key: Arc<Pk>,
                           ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
                           ca_crl: Option<Arc<Crl>>
) -> Result<(&'a ApplicationConfigConnectionDataset, Credentials), String> {

    let dataset = config.extra.connections.as_ref().ok_or("Missing connections in runtime config")?
                                          .get(port).ok_or(format!("Missing connection in runtime config for port: {}", port))?
                                          .values().next().ok_or(format!("No dataset provided in runtime config for port: {}", port))?
                                          .dataset.as_ref().ok_or(format!("first connection is not a dataset for port: {}", port))?;

    let sdkms_info = dataset.credentials.sdkms.as_ref().ok_or(format!("dataset.sdkms field is not present for connection on port: {}.", port))?;
    
    let response = get_sdkms_dataset(sdkms_info.credentials_url.clone(),
                                     sdkms_info.credentials_key_name.clone(),
                                     sdkms_info.sdkms_app_id,
                                     app_cert.clone(),
                                     key.clone(),
                                     ca_cert_list,
                                     ca_crl).map_err(|e| format!("Failed retrieving dataset: {:?}", e))?;

    Ok((dataset, decode_credentials(response)?))
}

fn process(decrypted: Vec<u8>) -> Result<String, String> {
    #[allow(non_snake_case)]
    #[derive(Debug, Deserialize)]
    struct Record {
        START: String,
        STOP: String,
        PATIENT: String,
        ENCOUNTER: String,
        CODE: String,
        DESCRIPTION: String,
    }
 
    let mut statistics = HashMap::<String, u32>::new();
    let mut count : u32 = 0;
    let mut rdr = csv::Reader::from_reader(&*decrypted);
    for i in rdr.deserialize() {
        let record: Record = i.map_err(|_| "Invalid CSV data".to_string())?;
        statistics.entry(record.DESCRIPTION).and_modify(|e| *e += 1).or_insert(1);
        count += 1;
    }
 
    let last_entry = statistics.iter().max_by(|a, b| a.1.cmp(&b.1)).ok_or("No entries in CSV")?;
    let top = last_entry.0;
    let freq = last_entry.1;
    let unique = statistics.len();
     
    let result = format!("count  {:<50}\nunique {:<50}\ntop    {:<50}\nfreq   {:<50}\nName: DESCRIPTION, dtype: object\n",
                         count, unique, top, freq);
 
    Ok(result)
}

pub fn get_ascii(bytes: &Vec<u8>, allow_newline: bool) -> String {
    bytes.iter().map(|b| {
        if (*b >= 32u8 && *b <= 126u8) || (allow_newline && *b == '\n' as u8) {
            *b as char
        } else {
            '.'
        }
    }).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub query_string: String,
    pub encryption: CredentialsEncryption,
}

pub fn decode_credentials(credentials: Blob) -> Result<Credentials, String> {
    let credentials = String::from_utf8(credentials.to_vec()).map_err(|e| format!("Failed UTF-8 decoding on credentials field: {:?}", e))?;
    let credentials : Credentials = serde_json::from_str(&credentials).map_err(|e| format!("Failed json deserialization for credentials, error: {:?}, credentials {}", e, credentials))?;
    Ok(credentials)
}
