/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#[cfg(all(not(target_env = "sgx"), feature = "reqwest"))]
fn main() {
    #[cfg(feature = "rustls-tls")]
    rustls_mbedcrypto_provider::mbedtls_crypto_provider()
        .install_default()
        .expect("install rustls mbedtls crypto provider");
    dcap_artifact_retrieval::cli::main()
}
