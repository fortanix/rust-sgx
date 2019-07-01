/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// For quick_error
#![recursion_limit="128"]
#![deny(warnings)]
extern crate byteorder;
extern crate pkix;
extern crate sgx_isa;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate lazy_static;

pub mod oid;
pub mod attestation;
pub mod pkcs10;
pub mod error;

pub use error::{Error, Result};
