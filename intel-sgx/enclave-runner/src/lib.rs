/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(raw_dylib_elf)]
#![allow(non_local_definitions, incomplete_features)] // Required by failure
#![deny(warnings)]
#![doc(
    html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
    html_favicon_url = "https://edp.fortanix.com/favicon.ico",
    html_root_url = "https://edp.fortanix.com/docs/api/"
)]

mod command;
mod library;
mod loader;
mod tcs;
pub mod usercalls;

pub use crate::command::Command;
pub use crate::library::Library;
pub use crate::loader::{EnclaveBuilder, EnclavePanic};
