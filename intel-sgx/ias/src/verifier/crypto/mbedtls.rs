/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use mbedtls::Error;
use mbedtls::hash::{Type,Md};
use mbedtls::pk::Pk;
use mbedtls;

use super::{private::Crypto, SHA256_DIGEST_LEN};

pub struct Mbedtls;

impl Crypto for Mbedtls {
    type Error = Error;

    fn sha256(message: &[u8], digest: &mut [u8; SHA256_DIGEST_LEN]) -> ::std::result::Result<(), Self::Error> {
        Md::hash(Type::Sha256, &message, digest)?;
        Ok(())
    }

    fn rsa_sha256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> ::std::result::Result<(), Self::Error> {
        let mut pk = Pk::from_public_key(public_key)?;

        let mut hash = vec![0; SHA256_DIGEST_LEN];
        Md::hash(Type::Sha256, &message, &mut hash)?;

        pk.verify(Type::Sha256, &hash, &signature)?;

        Ok(())
    }
}
