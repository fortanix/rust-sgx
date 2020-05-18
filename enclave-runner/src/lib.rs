/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(llvm_asm)]
#![doc(
    html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
    html_favicon_url = "https://edp.fortanix.com/favicon.ico",
    html_root_url = "https://edp.fortanix.com/docs/api/"
)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate lazy_static;

mod command;
mod library;
mod loader;
mod tcs;
pub mod usercalls;

pub use crate::command::Command;
pub use crate::library::Library;
pub use crate::loader::{EnclaveBuilder, EnclavePanic};
