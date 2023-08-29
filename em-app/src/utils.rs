/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::sync::Arc;
use std::io::Read;

pub use em_client::models;

use hyper::client::Pool;
use hyper::net::HttpsConnector;
use em_client::{Api, Client};
use mbedtls::alloc::{List as MbedtlsList};
use mbedtls::cipher::raw::{CipherId, CipherMode};
use mbedtls::cipher::{Decryption, Encryption, Fresh, Authenticated};
use mbedtls::cipher;
use mbedtls::pk::Pk;
use mbedtls::rng::{Rdrand, Random};
use mbedtls::ssl::Config;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version};
use mbedtls::x509::{Certificate, Crl};
use rustc_serialize::hex::FromHex;
use sdkms::api_model::Blob;
use uuid::Uuid;
use url::Url;
use std::time::Duration;
use uuid_sdkms::{Uuid as SdkmsUuid};

use crate::mbedtls_hyper::MbedSSLClient;

pub fn convert_uuid(api_uuid: Uuid) -> SdkmsUuid {
    SdkmsUuid::from_bytes(*api_uuid.as_bytes())
}

pub fn get_runtime_configuration(
    server: &str,
    port: u16,
    cert: Arc<MbedtlsList<Certificate>>,
    key: Arc<Pk>,
    ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
    ca_crl: Option<Arc<Crl>>
) -> Result<models::RuntimeAppConfig, String> {

    println!("Creating runtime config");
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_rng(Arc::new(mbedtls::rng::Rdrand));

    println!("runtime config rng");

    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    println!("runtime config tls");

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }
    
    config.push_cert(cert, key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    println!("runtime config certs");

    let ssl = MbedSSLClient::new_with_sni(Arc::new(config), true, Some(format!("nodes.{}", server)));

    println!("runtime config ssl client");

    let connector = HttpsConnector::new(ssl);
    let client = Client::try_new_with_connector(&format!("https://{}:{}/v1/runtime/app_configs", server, port), None, connector).map_err(|e| format!("EM SaaS request failed: {:?}", e))?;

    println!("runtime config https client");

    let response = client.get_runtime_application_config().map_err(|e| format!("Failed requesting workflow config response: {:?}", e))?;

    println!("runtime config response");

    Ok(response)
}

pub fn log_function() -> () {
    println!("Test log");
    log::info!("Test log");
    log::info!("Test log");
    log::info!("Test log");
}

pub fn get_sdkms_dataset(
    sdkms_url: String,
    dataset_id: String,
    app_id: Uuid,
    cert: Arc<MbedtlsList<Certificate>>,
    key: Arc<Pk>,
    ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
    ca_crl: Option<Arc<Crl>>
) -> Result<Blob, String> {

    println!("Creating config");

	log::info!("Creating config");
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    
    config.set_rng(Arc::new(mbedtls::rng::Rdrand));

    println!("Set rng");
    log::info!("Set rng");
    
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    println!("Set min version");
        log::info!("Set min version");

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }

    println!("Set something");
            log::info!("Set something");
    
    config.push_cert(cert, key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;
    println!("Pushed cert");
                log::info!("Pushed cert");
    
    let ssl = MbedSSLClient::new(Arc::new(config), true);
    println!("Created mbde ssl client");
                    log::info!("Created mbde ssl client");
    
    let connector = HttpsConnector::new(ssl);
    println!("Created ssl connector");
                        log::info!("Created ssl connector");
    
    let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), connector)));
    println!("Created ssl connector with something");
                        log::info!("Created ssl connector with something");

    let client = sdkms::SdkmsClient::builder()
        .with_api_endpoint(&sdkms_url)
        .with_hyper_client(client)
        .build().map_err(|e| format!("SDKMS Build failed: {:?}", e))?
        .authenticate_with_cert(Some(&convert_uuid(app_id))).map_err(|e| format!("SDKMS authenticate failed: {:?}", e))?;
    println!("Created sdkms client");
                        log::info!("Created sdkms client");

    let key_id = sdkms::api_model::SobjectDescriptor::Name(dataset_id);
    println!("Requesting sobject");
                            log::info!("Requesting sobject");
    
    let result = client.export_sobject(&key_id).map_err(|e| format!("Failed SDKMS export operation: {:?}", e))?;
    println!("Finished with sobject");
                                log::info!("Finished with sobject");
    
    let result1 = result.value.ok_or("Missing value in exported object".to_string());

    println!("Sobject result is {:?}", result1);

    result1
}

pub fn https_get(url: Url,
                 ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
                 ca_crl: Option<Arc<Crl>>
) -> Result<Vec<u8>, String> {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    
    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }

    let ssl = MbedSSLClient::new(Arc::new(config), true);
    let connector = HttpsConnector::new(ssl);
    let client = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));
    let mut response = client.get(url).send().map_err(|e| format!("Failed downloading, error: {:?}", e))?;

    if response.status != hyper::status::StatusCode::Ok {
        return Err(format!("Request failed, result: {:?}", response));
    }
    
    let mut body = vec![];
    response.read_to_end(&mut body).map_err(|e| format!("Failed reading body, error: {:?}", e))?;

    Ok(body)
}

pub fn https_put(url: Url,
                 body: Vec<u8>,
                 ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
                 ca_crl: Option<Arc<Crl>>
) -> Result<(), String> {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    
    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }

    let ssl = MbedSSLClient::new(Arc::new(config), true);
    let connector = HttpsConnector::new(ssl);
    let client = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));
    let result = client.put(url).body(body.as_slice()).send().map_err(|e| format!("Failed upload, error: {:?}", e))?;

    if result.status != hyper::status::StatusCode::Ok {
        return Err(format!("Request failed, result: {:?}", result));
    }
    
    Ok(())
}

const NONCE_SIZE : usize = 12;
const TAG_SIZE : usize = 16;

// Basic AES-256-GCM encrypt/decrypt utility functions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialsEncryption {
    pub key: String,
}

pub fn encrypt_buffer(body: &[u8], encryption: &CredentialsEncryption) -> Result<Vec<u8>, String>{
    let key = encryption.key.from_hex().map_err(|e| format!("Failed decoding key as a hex string: {:?}", e))?;

    let mut nonce = [0; NONCE_SIZE];
    Rdrand.random(&mut nonce[..]).map_err(|e| format!("Could not generate random nonce {}", e))?;

    let cipher = cipher::Cipher::<Encryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, 256).map_err(|e| format!("Failed creating cypher: {:?}", e))?;
    let cipher_k = cipher.set_key_iv(&key, &nonce).map_err(|e| format!("Failed setting key, error: {:?}", e))?;

    let mut output = Vec::new();
    output.resize(body.len() + NONCE_SIZE + TAG_SIZE + cipher_k.block_size(), 0);

    let size = cipher_k.encrypt_auth(&[], &body[..], &mut output[NONCE_SIZE..], TAG_SIZE).map_err(|e| format!("Failed encrypting body, error: {:?}", e))?.0;
    output.resize(size + NONCE_SIZE, 0);

    output[0..NONCE_SIZE].copy_from_slice(&nonce);

    Ok(output)
}

pub fn decrypt_buffer(body: &Vec<u8>, encryption: &CredentialsEncryption) -> Result<Vec<u8>, String>{
    let key = encryption.key.from_hex().map_err(|e| format!("Failed deconding key as a hex string: {:?}", e))?;
    
    let cipher = cipher::Cipher::<Decryption, Authenticated, Fresh>::new(CipherId::Aes, CipherMode::GCM, 256).map_err(|e| format!("Failed creating cypher: {:?}", e))?;
    let cipher_k = cipher.set_key_iv(&key, &body[0..NONCE_SIZE]).map_err(|e| format!("Failed setting key, error: {:?}", e))?;
    
    let mut decrypted = Vec::new();
    
    // Allocate the length + 1 block size more to have enough space for decrypted content
    decrypted.resize(body.len() + cipher_k.block_size(), 0);
    
    // Decrypt starting from byte 12 after our nonce and up to -TAG_SIZE which is 16 bytes
    let (size, _cipher_f) = cipher_k.decrypt_auth(&[], &body[NONCE_SIZE..], &mut decrypted, TAG_SIZE).map_err(|e| format!("Failed decrypting body, error: {:?}", e))?;
    
    decrypted.resize(size, 0);
    Ok(decrypted)
}

const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 30;

pub fn get_hyper_connector_pool(ca_chain: Vec<Vec<u8>>) -> Result<Arc<hyper::Client>, String> {
    get_mbedtls_hyper_connector_pool(ca_chain, None)
}

pub fn get_mbedtls_hyper_connector_pool(ca_chain: Vec<Vec<u8>>, client_pki: Option<(Arc<MbedtlsList<Certificate>>, Arc<Pk>)>) -> Result<Arc<hyper::Client>, String> {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    if !ca_chain.is_empty() {
        let mut list = MbedtlsList::<Certificate>::new();
        for i in ca_chain {
            list.push(Certificate::from_der(&i).map_err(|e| format!("Failed parsing ca cert, error: {:?}", e))?);
        }

        config.set_ca_list(Arc::new(list), None);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }

    if let Some((cert, key)) = client_pki {
        config.push_cert(cert, key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;
    }
    
    let ssl = MbedSSLClient::new(Arc::new(config), true);
    let connector = HttpsConnector::new(ssl);

    let mut pool = Pool::with_connector(Default::default(), connector);
    pool.set_idle_timeout(Some(Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS)));

    Ok(Arc::new(hyper::Client::with_connector(pool)))
}
