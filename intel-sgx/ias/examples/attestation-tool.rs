/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;

use std::fmt;
use std::mem;
use std::str;

use ias::api::{ENCLAVE_QUOTE_BODY_LEN, IasAdvisoryId, IasVersion, LATEST_IAS_VERSION, PlatformStatus, QuoteStatus, Unverified, VerifyAttestationEvidenceRequest};
use ias::verifier::{AttestationEmbeddedIasReport, Error, Platform};
use ias::verifier::crypto::Mbedtls;
use ias::client::ClientBuilder;
use aesm_client::{AesmClient, QuoteType};
use once_cell::sync::Lazy;
use pkix::pem::{self, PEM_CERTIFICATE};
use sgxs_loaders::isgx::Device as IsgxDevice;
use sgx_isa::Targetinfo;

const IAS_PROXY_URL: &'static str = "https://iasproxy.fortanix.com/";
const IAS_PROD_OLD_URL: &'static str = "https://as.sgx.trustedservices.intel.com/";
const IAS_DEV_OLD_URL: &'static str = "https://test-as.sgx.trustedservices.intel.com/";
const IAS_PROD_URL: &'static str = "https://api.trustedservices.intel.com/sgx/";
const IAS_DEV_URL: &'static str = "https://api.trustedservices.intel.com/sgx/dev/";

const REPORT_BODY_HEADER_SIZE: usize = 48; // the part not from enclave's REPORT
const REPORT_SIZE_TRUNCATED: usize = 384; // without KEYID, MAC

static IAS_REPORT_SIGNING_CERTIFICATE: Lazy<Vec<u8>> = Lazy::new(|| {
    pem::pem_to_der(include_str!("../tests/data/test_report_signing_cert"),
                   Some(PEM_CERTIFICATE)).unwrap()
});

struct IgnorePlatformState;

impl IgnorePlatformState {
    fn new() -> IgnorePlatformState {
        IgnorePlatformState {}
    }
}

impl Platform for IgnorePlatformState {
    fn verify(&self, _for_self: bool, _nonce: &Option<String>, _isv_enclave_quote_status: QuoteStatus, _advisories: &Vec<IasAdvisoryId>) -> Result<(), Error> {
        Ok(())
    }
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
            let report: AttestationEmbeddedIasReport<Unverified> = response
                .clone()
                .into();
            let report = report
                .verify::<Mbedtls>(&[IAS_REPORT_SIGNING_CERTIFICATE.as_slice()])
                .and_then(|rep| {
                    rep
                        .to_attestation_evidence_reponse()?
                        .verify(&IgnorePlatformState::new())
                });

            let report = match report {
                Ok(report) => report,
                Err(err) => {
                    println!("IAS verification error:");
                    println!("  {}", err);
                    return;
                }
            };

            let pstatus = report.platform_info_blob().as_ref()
                .map(|v| v.parse::<PlatformStatus>().map_err(|_| v.to_owned()));

            let report_body_header = unsafe { mem::transmute::<_, [u8; ENCLAVE_QUOTE_BODY_LEN]>(report.isv_enclave_quote_body()) };
            println!("");
            println!("IAS report contents:");
            println!("  id: {}", report.id());
            println!("  version: {}", report.version());
            println!("  isv_enclave_quote_status: {:?}", report.isv_enclave_quote_status());
            println!("  isv_enclave_quote_body header: {}", HexPrint(&report_body_header[0..REPORT_BODY_HEADER_SIZE]));
            println!("  revocation_resason: {:?}", report.revocation_reason());
            println!("  pse_manifest_status: {:?}", report.pse_manifest_status());
            println!("  pse_manifest_hash: {:?}", report.pse_manifest_hash());
            println!("  platform_info_blob: {:?}", report.platform_info_blob());
            println!("  nonce: {:?}", report.nonce());
            println!("  epid_pseudonym: {}", report.epid_pseudonym().as_ref().map_or_else(|| Box::new("None") as Box<dyn fmt::Display>, |v| Box::new(HexPrint(&v))));

            if pstatus.is_some() {
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

            let response: sgx_pkix::attestation::AttestationEmbeddedIasReport = response.into();
            if matches.is_present("DUMP") {
                println!("");
                println!("IAS report dump:");
                println!("  report: {}", HexPrint(&response.http_body));
                println!("  signature: {}", HexPrint(&response.report_sig));
                for cert in &response.certificates {
                    let pem = pkix::pem::der_to_pem(&cert, pkix::pem::PEM_CERTIFICATE);
                    println!("  certificate: {}", pem);
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
