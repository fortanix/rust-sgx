/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
//! The ability to attest that an enclave is executing on a trustworthy platform, is a key feature
//! of Intel SGX. This crate enables users to communicate with the IAS service to verify (EPID)
//! attestations.
//! The normal flow for using IAS is to create an IAS client with
//! `client::ClientBuilder::build()`, call the `get_sig_rl` and `verify_quote`
//! APIs, then call `verifier::quote`.
//!
//! ## Feature flags
#![doc = document_features::document_features!()]

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;

pub mod api;
#[cfg(feature = "client")]
pub mod client;
pub mod verifier;

use std::fmt;

#[cfg(all(feature = "manipulate_attestation", not(debug_assertions)))]
compile_error!("The 'manipulate_attestation' feature is only available in debug mode.");

struct HexPrint<'a>(&'a [u8]);
impl<'a> fmt::Display for HexPrint<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?
        }
        Ok(())
    }
}
