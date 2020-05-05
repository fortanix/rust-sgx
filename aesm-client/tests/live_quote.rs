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

pub fn get_algorithm_id(key_id : &Vec<u8>) -> u32 {
    const ALGORITHM_OFFSET : usize = 154;

    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET+4]);
    u32::from_le_bytes(bytes)
}

#[cfg(not(windows))]
#[test]
fn test_ecdsa_quote() {
    const NONCE: [u8; 16] = [0; 16];
    const SGX_QL_ALG_ECDSA_P256 : u32 = 2;

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let key_ids = client.get_supported_att_key_ids().unwrap();
    println!("KeyIDs: {:?}", key_ids);

    // Select the ECDSA key that will be used later, if ECDSA is not supported the key id is still present - https://github.com/intel/linux-sgx/issues/536
    let ecdsa_key_id = key_ids.into_iter().find(|id| SGX_QL_ALG_ECDSA_P256 == get_algorithm_id(id));

    if let Some(key) = ecdsa_key_id {
        // If this fails with 'AesmCode(UnexpectedError_1)' then ECDSA is likely not supported on this platform.
        let quote_info = client.init_quote_ex(key.clone()).unwrap();
        println!("QuoteInfoEx: {:x?}", quote_info);

        let ti = Targetinfo::try_copy_from(&quote_info.target_info).unwrap();
        let report = report_test::report(&ti, &mut device).unwrap();
        
        let res = client.get_quote_ex(key, report.as_ref().to_owned(), quote_info, &NONCE).unwrap();
        println!("GetQuoteEx response: {:x?}", res);
    }
}
