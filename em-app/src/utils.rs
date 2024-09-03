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
use mbedtls::pk::Pk;
use mbedtls::ssl::Config;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version};
use mbedtls::x509::{Certificate, Crl};
use mbedtls::hash::{Md, Type};
use sdkms::api_model::Blob;
use uuid::Uuid;
use url::Url;
use std::time::Duration;
use uuid_sdkms::{Uuid as SdkmsUuid};

use crate::mbedtls_hyper::MbedSSLClient;

pub fn convert_uuid(api_uuid: Uuid) -> SdkmsUuid {
    SdkmsUuid::from_bytes(*api_uuid.as_bytes())
}

/// Computes a Sha256 hash of an input
pub fn compute_sha256(input: &[u8]) -> Result<[u8; 32], String> {
    let mut digest = [0; 32];
    Md::hash(Type::Sha256, input, &mut digest)
        .map_err(|e| format!("Error in calculating digest: {:?}", e))?;

    Ok(digest)
}

pub fn get_runtime_configuration(
    server: &str,
    port: u16,
    cert: Arc<MbedtlsList<Certificate>>,
    key: Arc<Pk>,
    ca_cert_list: Option<Arc<MbedtlsList<Certificate>>>,
    ca_crl: Option<Arc<Crl>>,
    expected_hash: &[u8; 32]
) -> Result<models::RuntimeAppConfig, String> {

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);

    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }
    
    config.push_cert(cert, key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;
    
    let ssl = MbedSSLClient::new_with_sni(Arc::new(config), true, Some(format!("nodes.{}", server)));
    let connector = HttpsConnector::new(ssl);
    let client = Client::try_new_with_connector(&format!("https://{}:{}/v1/runtime/app_configs", server, port), None, connector).map_err(|e| format!("EM SaaS request failed: {:?}", e))?;
    let response = client.get_runtime_application_config(expected_hash).map_err(|e| format!("Failed requesting workflow config response: {:?}", e))?;

    Ok(response)
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

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    
    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config.set_min_version(Version::Tls1_2).map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    if let Some(ca_cert_list) = ca_cert_list {
        config.set_ca_list(ca_cert_list, ca_crl);
        config.set_authmode(AuthMode::Required);
    } else {
        config.set_authmode(AuthMode::Optional);
    }
    
    config.push_cert(cert, key).map_err(|e| format!("TLS configuration failed: {:?}", e))?;
    
    let ssl = MbedSSLClient::new(Arc::new(config), true);
    let connector = HttpsConnector::new(ssl);
    let client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), connector)));

    let client = sdkms::SdkmsClient::builder()
        .with_api_endpoint(&sdkms_url)
        .with_hyper_client(client)
        .build().map_err(|e| format!("SDKMS Build failed: {:?}", e))?
        .authenticate_with_cert(Some(&convert_uuid(app_id))).map_err(|e| format!("SDKMS authenticate failed: {:?}", e))?;

    let key_id = sdkms::api_model::SobjectDescriptor::Name(dataset_id);
    
    let result = client.export_sobject(&key_id).map_err(|e| format!("Failed SDKMS export operation: {:?}", e))?;
    
    result.value.ok_or("Missing value in exported object".to_string())
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
