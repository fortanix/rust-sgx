/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "mbedtls")]
mod mbedtls;

#[cfg(feature = "mbedtls")]
pub use self::mbedtls::Mbedtls;

pub const SHA256_DIGEST_LEN: usize = 32;

pub(super) mod private {
    pub trait Crypto {
        type Error: std::error::Error + Send + Sync + 'static;

        /// Compute the SHA256 hash of `message` and return it in `digest`.
        fn sha256(message: &[u8], digest: &mut [u8; super::SHA256_DIGEST_LEN]) -> ::std::result::Result<(), Self::Error>;

        /// Verify the PKCS#1 v1.5 `RSA` signature on `message` using `public_key`
        /// and SHA256.
        ///
        /// Returns `Ok(())` if the signature is correct, an error otherwise.
        fn rsa_sha256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> ::std::result::Result<(), Self::Error>;
    }
}
