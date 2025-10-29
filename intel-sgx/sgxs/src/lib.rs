/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]

extern crate byteorder;
extern crate thiserror;
#[cfg(feature = "crypto-openssl")]
extern crate foreign_types;
#[cfg(feature = "crypto-openssl")]
extern crate openssl;
#[cfg(feature = "crypto-openssl")]
extern crate openssl_sys;
extern crate sgx_isa as abi;
#[cfg(feature = "sha2")]
extern crate sha2;
extern crate time;

pub mod crypto;
pub mod einittoken;
pub mod loader;
pub mod sgxs;
pub mod sigstruct;
pub mod util;

#[cfg(target_endian = "big")]
compile_error!("Big endianness not supported");
