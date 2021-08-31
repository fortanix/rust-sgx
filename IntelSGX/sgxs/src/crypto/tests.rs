/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![cfg_attr(not(feature="crypto-openssl"),allow(unused))]

use super::*;

const N: &'static [u8] = include_bytes!("../../tests/data/sig1.key_n.bin");
const KEY: &'static [u8] = include_bytes!("../../tests/data/sig1.key.pem");
const H: &'static [u8] = include_bytes!("../../tests/data/sig1.data.bin");
const S: &'static [u8] = include_bytes!("../../tests/data/sig1.sig.bin");
const Q1: &'static [u8] = include_bytes!("../../tests/data/sig1.q1.bin");
const Q2: &'static [u8] = include_bytes!("../../tests/data/sig1.q2.bin");

fn test_rsa<K: SgxRsaOps>(key: &K) {
    assert_eq!(key.len(), 3072);
    assert_eq!(&key.n()[..], N);
    assert_eq!(&key.e()[..], [3]);
    let (sig, q1, q2) = key.sign_sha256_pkcs1v1_5_with_q1_q2(H).unwrap();
    assert_eq!(&sig[..], S);
    assert_eq!(&q1[..], Q1);
    assert_eq!(&q2[..], Q2);
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn openssl_rsa() {
    use openssl::pkey::PKey;

    let key = PKey::private_key_from_pem(KEY).unwrap();
    test_rsa(&*key.rsa().unwrap())
}
