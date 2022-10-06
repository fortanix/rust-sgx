/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;

use std::fmt;
use std::str;

use aesm_client::{AesmClient, QuoteType};
use ias::api::{IasVersion, LATEST_IAS_VERSION, PlatformStatus, VerifyAttestationEvidenceRequest};
use ias::client::ClientBuilder;
use ias::verifier::crypto::Mbedtls;
use pkix::pem::{self, PEM_CERTIFICATE};
use sgxs_loaders::isgx::Device as IsgxDevice;
use sgx_isa::Targetinfo;

const IAS_PROXY_URL: &'static str = "https://iasproxy.fortanix.com/";
const IAS_PROD_OLD_URL: &'static str = "https://as.sgx.trustedservices.intel.com/";
const IAS_DEV_OLD_URL: &'static str = "https://test-as.sgx.trustedservices.intel.com/";
const IAS_PROD_URL: &'static str = "https://api.trustedservices.intel.com/sgx/";
const IAS_DEV_URL: &'static str = "https://api.trustedservices.intel.com/sgx/dev/";

const REPORT_SIZE_TRUNCATED: usize = 384; // without KEYID, MAC

lazy_static::lazy_static!{
    // This is the IAS report signing certificate.
    static ref TEST_REPORT_SIGNING_CERT: Vec<u8> =
        pem::pem_to_der(include_str!("../tests/data/reports/test_report_signing_cert"),
                Some(PEM_CERTIFICATE)).unwrap();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();

    let matches = clap_app!(attestation_tool =>
        (author: "Fortanix")
        (about: "SGX Remote Attestation Tool")
        (@arg IAS_URL: --("ias") +required +takes_value default_value("ftx-proxy") "URL of the IAS to use, or one of the special values \"intel-dev\", \"intel-liv\", \"ftx-proxy\". Attestation will be skipped if this parameter is not specified.")
        (@arg ALT_PATH: --("ias-alt-path") "Use the alternate IAS API paths (default for version 4 and up)")
        (@arg VERSION: --("version") +takes_value "IAS version to use (2, 3, 4)")
        (@arg SUBSCRIPTION_KEY: --("subscription-key") +takes_value conflicts_with("CERTIFICATE") "Subscription key to use to authenticate to IAS")
        (@arg CERTIFICATE: --("client-cert") +takes_value requires("CERTIFICATE_PASS") "Filename of a certificate and private key in PKCS#12 format to use to authenticate to IAS")
        (@arg CERTIFICATE_PASS: --("client-cert-password") +takes_value "Password for PKCS#12 file")
        (@arg DUMP: --("dump") "Dump the report in hex")
        (@arg SPID: --("spid") +takes_value "SPID to use")
    ).get_matches();

    let version = match matches.value_of("VERSION") {
        None => LATEST_IAS_VERSION,
        Some("2") => IasVersion::V2,
        Some("3") => IasVersion::V3,
        Some("4") => IasVersion::V4,
        Some(v) => {
            println!("Unable to parse IAS version: {}", v);
            return
        }
    };
    let use_alt = matches.is_present("ALT_PATH")  || version >= IasVersion::V4;

    let url = match (matches.value_of("IAS_URL").expect("required"), use_alt) {
        ("intel-dev", false) => IAS_DEV_OLD_URL,
        ("intel-dev", true) => IAS_DEV_URL,
        ("intel-liv", false) => IAS_PROD_OLD_URL,
        ("intel-liv", true) => IAS_PROD_URL,
        ("ftx-proxy", _) => IAS_PROXY_URL,
        (url, _) => url,
    };

    println!("Using IAS URL: {}", url);

    let mut builder = ClientBuilder::new();
    if use_alt {
        builder = builder.use_alternate_api_path(true);
    }
    if let Some(subscription_key) = matches.value_of("SUBSCRIPTION_KEY") {
        builder = builder.subscription_key(subscription_key.to_owned());
    }
    #[cfg(feature = "client-certificate")]
    if let (Some(client_certificate), Some(pass)) = (matches.value_of("CERTIFICATE"), matches.value_of("CERTIFICATE_PASS")) {
        let p12_file = std::fs::read(client_certificate).unwrap();
        let identity = reqwest::tls::Identity::from_pkcs12_der(&p12_file, pass).unwrap();
        builder = builder.client_certificate(identity);
    }
    let ias_client = builder.ias_version(version).build(url).unwrap();

    let aesm_client = AesmClient::new();

    let quote = aesm_client.init_quote().unwrap();

    let ti = Targetinfo::try_copy_from(quote.target_info()).unwrap();

    let mut loader = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let report = report_test::report(&ti, &mut loader).unwrap();

    println!("Enclave report contents:");
    println!("  CPUSVN: {}", HexPrint(&report.cpusvn));
    println!("  MISCSELECT: {:?}", report.miscselect);
    println!("  ATTRIBUTES: {:?}", report.attributes);
    println!("  MRENCLAVE: {}", HexPrint(&report.mrenclave));
    println!("  MRSIGNER: {}", HexPrint(&report.mrsigner));
    println!("  ISVPRODID: {}", report.isvprodid);
    println!("  ISVSVN: {}", report.isvsvn);
    println!("  KEYID: {}", HexPrint(&report.keyid));
    println!("  MAC: {}", HexPrint(&report.mac));

    let spid = match matches.value_of("SPID") {
        Some(spid) => from_hex(spid),
        None => ias_client.get_spid(&report.as_ref()[..REPORT_SIZE_TRUNCATED]).await.unwrap(),
    };

    let sig_rl = ias_client.get_sig_rl(&quote.gid(), Some(&spid)).await.unwrap_or(vec![]);

    let quote = aesm_client.get_quote(
        report.as_ref().to_owned(),
        spid,
        sig_rl,
        QuoteType::Linkable,
        vec![0;16]
    ).unwrap();

    let req = VerifyAttestationEvidenceRequest {
        isv_enclave_quote: quote.quote().to_owned(),
        pse_manifest: None,
        nonce: None,
    };
    println!("  QUOTE: {}", base64::encode(req.isv_enclave_quote));

    match ias_client.verify_quote(quote.quote()).await {
        Ok(response) => {
            let report = response
                .report::<Mbedtls>(&[TEST_REPORT_SIGNING_CERT.as_slice()])
                .expect("Corrupt report");

            let pstatus = report.platform_info_blob().as_ref()
                .map(|v| v.parse::<PlatformStatus>().map_err(|_| v.to_owned()));

            println!("");
            println!("IAS report contents:");
            println!("  id: {}", report.id());
            println!("  version: {}", report.version());
            println!("  isv_enclave_quote_status: {:?}", report.isv_enclave_quote_status());
            println!("  isv_enclave_quote_body header");
            println!("    version: {}", report.isv_enclave_quote_body().version);
            println!("    signature type: {}", report.isv_enclave_quote_body().signature_type);
            println!("    gid: {}", HexPrint(&report.isv_enclave_quote_body().gid));
            println!("    isvsvn qe: {}", report.isv_enclave_quote_body().isvsvn_qe);
            println!("    isvsvn pce: {}", report.isv_enclave_quote_body().isvsvn_pce);
            println!("    basename: {}", HexPrint(&report.isv_enclave_quote_body().basename));
            println!("  revocation_resason: {:?}", report.revocation_reason());
            println!("  pse_manifest_status: {:?}", report.pse_manifest_status());
            println!("  pse_manifest_hash: {:?}", report.pse_manifest_hash());
            println!("  platform_info_blob: {:?}", report.platform_info_blob());
            println!("  nonce: {:?}", report.nonce());
            println!("  epid_pseudonym: {}", report.epid_pseudonym().as_ref().map_or_else(|| Box::new("None") as Box<dyn fmt::Display>, |v| Box::new(HexPrint(&v))));

            if pstatus.is_some() || response.advisory_url.is_some() || response.advisory_ids.is_empty() {
                println!("");
            }

            if let Some(ref s) = pstatus {
                println!("Platform status:");
                println!("  {:?}", s);
            }

            if let Some(ref s) = response.advisory_url {
                println!("Advisory URL: {}", s);
            }

            if !response.advisory_ids.is_empty() {
                println!("Advisory IDs: {}", response.advisory_ids.iter().map(|adv| adv.as_str().to_string()).collect::<Vec<String>>().join(", "));
            }

            if matches.is_present("DUMP") {
                println!("");
                println!("IAS report dump:");
                println!("  report: {}", HexPrint(&response.raw_report));
                println!("  signature: {}", HexPrint(&response.signature));
                for cert in &response.cert_chain {
                    println!("  certificate: {}", HexPrint(&cert));
                }
            }
        },
        Err(err) => {
            println!("IAS error:");
            println!("  {}", err);
        }
    }
}

fn from_hex(mut hex: &str) -> Vec<u8> {
    let mut ret = Vec::with_capacity(hex.len() / 2);
    loop {
        match hex.len() {
            0 => break,
            1 => panic!("Invalid hex string"),
            _ => {},
        };
        let (front, rest) = hex.split_at(2);
        hex = rest;
        ret.push(u8::from_str_radix(front, 16).unwrap());
    }
    ret
}

struct HexPrint<'a>(&'a [u8]);
impl<'a> fmt::Display for HexPrint<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?
        }
        Ok(())
    }
}
