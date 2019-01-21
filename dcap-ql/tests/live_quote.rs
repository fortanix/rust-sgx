/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate dcap_ql;
extern crate report_test;
extern crate sgxs;
extern crate sgxs_loaders;

use std::env;

use dcap_ql::quote;
use dcap_ql::quote::CertificationDataType::*;
use sgxs_loaders::sgx_enclave_common::Library as EnclaveCommonLibrary;

fn parse_live_quote(mut loader: impl sgxs::loader::Load) {
    let var = env::var("DCAP_QL_TEST_ATT_KEY_TYPE").map(|mut s| {
        s.make_ascii_lowercase();
        s
    });

    let cd_type = match var.as_ref().map(String::as_str) {
        Ok("ppid_encrypted_rsa3072") => PpidEncryptedRsa3072,
        Ok("pck_cert_chain") => PckCertificateChain,
        Err(env::VarError::NotPresent) => {
            eprintln!(
                "DCAP_QL_TEST_ATT_KEY_TYPE envvar not set, assuming 'ppid_encrypted_rsa3072'."
            );
            PpidEncryptedRsa3072
        }
        _ => panic!(
            "Invalid value for DCAP_QL_TEST_ATT_KEY_TYPE: {}",
            env::var_os("DCAP_QL_TEST_ATT_KEY_TYPE")
                .unwrap()
                .to_string_lossy()
        ),
    };

    let ti = dcap_ql::target_info().unwrap();
    let report = report_test::report(&ti, &mut loader).unwrap();
    let quote = dcap_ql::quote(&report).unwrap();
    let quote = quote::Quote::parse(&quote).unwrap();
    let sig = quote
        .signature::<quote::Quote3SignatureEcdsaP256>()
        .unwrap();

    assert_eq!(sig.certification_data_type(), cd_type);
}

#[test]
fn parse_live_quote_load_ql() {
    parse_live_quote(EnclaveCommonLibrary::load(None).unwrap().build());
}

#[cfg(feature = "link")]
#[test]
fn parse_live_quote_link_ql() {
    parse_live_quote(dcap_ql::enclave_loader().unwrap());
}
