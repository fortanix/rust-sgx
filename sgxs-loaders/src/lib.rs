/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]

#[cfg(unix)] #[macro_use]
extern crate nix as ioctl_crate;
extern crate failure;
#[cfg(unix)]
extern crate libc;
extern crate sgx_isa as abi;
extern crate sgxs as sgxs_crate;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate bitflags;
#[cfg(windows)] extern crate winapi;

mod generic;
#[cfg(unix)] pub mod isgx;
pub mod sgx_enclave_common;
#[cfg(windows)] pub mod enclaveapi;

use std::fmt::Debug;
use std::os::raw::c_void;
use std::sync::Arc;

use sgxs_crate::loader;

#[derive(Debug)]
pub struct Tcs {
    _mapping: Arc<Debug + Sync + Send>,
    address: u64,
}

impl loader::Tcs for Tcs {
    fn address(&self) -> *mut c_void {
        self.address as _
    }
}

#[derive(Debug)]
pub struct MappingInfo {
    _mapping: Arc<Debug + Sync + Send>,
    base: u64,
    size: u64,
}

impl loader::MappingInfo for MappingInfo {
    fn address(&self) -> *mut c_void {
        self.base as _
    }

    fn size(&self) -> usize {
        self.size as _
    }
}
