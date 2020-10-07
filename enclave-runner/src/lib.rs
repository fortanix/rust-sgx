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

use std::fmt::Debug;

mod command;
mod library;
mod loader;
mod tcs;
pub mod usercalls;

pub use crate::command::Command;
pub use crate::library::Library;
pub use crate::loader::{EnclaveBuilder, EnclavePanic};

use sgxs::loader::{MappingInfo, EnclaveControl};

trait MappingInfoDynController: Debug {
    fn dyn_controller(&self) -> Option<&dyn EnclaveControl>;
}

impl<T> MappingInfoDynController for T where T: MappingInfo, T::EnclaveControl: Sized {
    fn dyn_controller(&self) -> Option<&dyn EnclaveControl> {
        self.enclave_controller().map(|c| c as _)
    }
}

