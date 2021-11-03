/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]

extern crate byteorder;
#[macro_use]
extern crate failure;
#[cfg(all(feature="bindings", not(feature = "link")))]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "verify")]
extern crate mbedtls;
#[macro_use]
extern crate num_derive;
extern crate num_traits;
#[cfg(all(test, feature = "verify"))]
extern crate serde;
extern crate sgx_isa;


pub mod quote;
#[cfg(feature = "bindings")]
mod bindings;

#[cfg(feature = "bindings")]
pub use bindings::*;

