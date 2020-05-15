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

use aesm_client::{AesmClient, QuoteType};
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
    let quote = client
        .get_quote(
            report.as_ref().to_owned(),
            DUMMY_SPID.to_vec(),
            vec![],
            QuoteType::Linkable,
            [0; 16].to_vec(),
        )
        .expect("quote result");

    assert_eq!(quote.qe_report().len(), sgx_isa::Report::UNPADDED_SIZE);
}

pub fn get_algorithm_id(key_id : &Vec<u8>) -> u32 {
    const ALGORITHM_OFFSET : usize = 154;

    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET+4]);
    u32::from_le_bytes(bytes)
}

#[cfg(not(windows))]
#[test]
fn live_quote_ex_ecdsa() {
    const SGX_QL_ALG_ECDSA_P256 : u32 = 2;

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let key_ids = client.get_supported_att_key_ids().unwrap();

    // Select the ECDSA key that will be used later, if ECDSA is not supported the key id is still present - https://github.com/intel/linux-sgx/issues/536
    let ecdsa_key_id = key_ids.into_iter().find(|id| SGX_QL_ALG_ECDSA_P256 == get_algorithm_id(id)).expect("ECDSA attestation key not available");

    // If this fails with 'AesmCode(UnexpectedError_1)' then ECDSA is likely not supported on this platform.
    let quote_info = client.init_quote_ex(ecdsa_key_id.clone()).unwrap();

    let ti = Targetinfo::try_copy_from(quote_info.target_info()).unwrap();
    let report = report_test::report(&ti, &mut device).unwrap();

    let res = client.get_quote_ex(ecdsa_key_id, report.as_ref().to_owned(), None, vec![0; 16]).unwrap();

    assert_eq!(res.qe_report().len(), sgx_isa::Report::UNPADDED_SIZE);
}

#[cfg(not(windows))]
#[test]
fn live_quote_epid_compare_ex() {
    const AESM_QUOTING_TYPE_EPID_UNLINKABLE: u32 = 0;

    let client = AesmClient::new();

    let key_ids = client.get_supported_att_key_ids().unwrap();

    // Select the ECDSA key that will be used later, if ECDSA is not supported the key id is still present - https://github.com/intel/linux-sgx/issues/536
    let epid_key_id = key_ids.into_iter().find(|id| AESM_QUOTING_TYPE_EPID_UNLINKABLE == get_algorithm_id(id)).expect("EPID attestation key not available");

    let quote_info = client.init_quote().unwrap();
    let quote_info_ex = client.init_quote_ex(epid_key_id).unwrap();

    assert_eq!(quote_info.gid(), quote_info_ex.gid());
}
