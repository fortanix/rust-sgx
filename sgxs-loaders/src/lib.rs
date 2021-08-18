/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]

extern crate cty;

#[cfg(unix)] #[macro_use]
extern crate nix;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate bitflags;

mod generic;
#[cfg(unix)] pub mod isgx;
#[cfg(unix)] pub use isgx::EnclaveController;
#[cfg(unix)] use sgxs::loader::EnclaveControl;
pub mod sgx_enclave_common;
#[cfg(windows)] pub mod enclaveapi;

use std::fmt::Debug;
use std::os::raw::c_void;
use std::sync::Arc;

use sgxs::loader;

#[derive(Debug)]
pub struct Tcs {
    _mapping: Arc<dyn Debug + Sync + Send>,
    address: u64,
}

impl loader::Tcs for Tcs {
    fn address(&self) -> *mut c_void {
        self.address as _
    }
}

#[derive(Debug)]
pub struct MappingInfo<C> {
    _mapping: Arc<dyn Debug + Sync + Send>,
    base: u64,
    size: u64,
    enclave_controller: Option<C>
}

impl<C: EnclaveControl> loader::MappingInfo for MappingInfo<C> {
    type EnclaveControl = C;

    fn address(&self) -> *mut c_void {
        self.base as _
    }

    fn size(&self) -> usize {
        self.size as _
    }

    fn enclave_controller(&self) -> Option<&Self::EnclaveControl> {
        self.enclave_controller.as_ref()
    }
}
