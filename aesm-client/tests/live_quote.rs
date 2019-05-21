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

use aesm_client::AesmClient;
use sgx_isa::TargetInfo;
use sgxs_loaders::isgx::Device as IsgxDevice;

#[test]
fn live_quote() {
    const DUMMY_SPID: [u8; 16] = [0; 16];

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let quoteinfo = client.init_quote().expect("init quote");
    let ti = TargetInfo::try_copy_from(quoteinfo.target_info()).unwrap();
    let report = report_test::report(&ti, &mut device).unwrap();
    let _quote = client
        .get_quote(
            &quoteinfo,
            report.as_ref().to_owned(),
            DUMMY_SPID.to_vec(),
            vec![],
        )
        .expect("quote result");
}
