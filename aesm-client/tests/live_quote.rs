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

use sgx_types::{sgx_att_key_id_ext_t};
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

    // Print the keys for debugging
    for i in key_ids.iter() {
        let ptr = i.as_ptr() as *const sgx_att_key_id_ext_t;
        unsafe {
            println!("att_key_type: {:?}; spid: {:?}; base: id {:?}; version: {:?}; mrsigner_length {:?}; mrsigner {:?}; prod_id {:?}; extended_prod_id {:?}; config_id {:?}; family_id {:?}; algorithm_id {:?}",
                     (*ptr).att_key_type, (*ptr).spid, (*ptr).base.id, (*ptr).base.version, (*ptr).base.mrsigner_length,
                     (*ptr).base.mrsigner.split_at(16), (*ptr).base.prod_id, (*ptr).base.extended_prod_id, (*ptr).base.config_id.split_at(16), (*ptr).base.family_id, (*ptr).base.algorithm_id);
        }
    }

    // Select the ECDSA key that will be used later
    let ecdsa_key_id = key_ids.into_iter().find(|id| SGX_QL_ALG_ECDSA_P256 == get_algorithm_id(id));

    if let Some(key) = ecdsa_key_id {
        match client.init_quote_ex(key.clone()) {
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
                
                let res = client.get_quote_ex(key, report.as_ref().to_owned(), quote_info, &NONCE);
                println!("GetQuoteEx response: {:x?}", res);
            }
        }
    }
}
