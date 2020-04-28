/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate report_test;
extern crate sgx_isa;
extern crate sgxs;
extern crate sgxs_loaders;
extern crate sgx_types;

use sgx_types::sgx_ql_attestation_algorithm_id_t;
use aesm_client::{AesmClient, QuoteType, AesmError, Error};
use sgx_isa::Targetinfo;
#[cfg(unix)]
use sgxs_loaders::isgx::Device as IsgxDevice;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as IsgxDevice;
#[test]
fn live_quote() {
    const DUMMY_SPID: [u8; 16] = [0; 16];

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let quoteinfo = client.init_quote().expect("init quote");
    let ti = Targetinfo::try_copy_from(quoteinfo.target_info()).unwrap();
    
    let report = report_test::report(&ti, &mut device).unwrap();
    let _quote = client
        .get_quote(
            &quoteinfo,
            report.as_ref().to_owned(),
            DUMMY_SPID.to_vec(),
            vec![],
            QuoteType::Linkable,
            [0; 16].to_vec(),
        )
        .expect("quote result");
}

#[cfg(not(windows))]
#[test]
fn test_ecdsa_quote() {
    const NONCE: [u8; 16] = [0; 16];

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let keys = client.get_supported_att_key_ids().unwrap();
    let ecdsa_key = keys.select_algorithm_id(sgx_ql_attestation_algorithm_id_t::SGX_QL_ALG_ECDSA_P256).unwrap();

    if let Some(key) = ecdsa_key {
        match client.init_quote_ex(key) {
            Err(Error::AesmCode(AesmError::UnexpectedError_1)) => {
                // Note: We get a key for ECSA even on non-supported hardware.
                // Only signal that it may not be supported is this error code when trying to init quote.
                println!("Unsupported ECDSA operation on current hardware");
                return;
            },
            Err(error) => { panic!("Error in init_quote_ecdsa: {:?}", error); },
            Ok(quote_info) => {
                println!("QuoteInfoEx: {:x?}", quote_info);

                let ti = Targetinfo::try_copy_from(&quote_info.target_info).unwrap();
                let report = report_test::report(&ti, &mut device).unwrap();
                
                let res = client.get_quote_ex(report.as_ref().to_owned(), quote_info, &NONCE);
                println!("GetQuoteEx response: {:x?}", res);
            }
        }
    }
}
