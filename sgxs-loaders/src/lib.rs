/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(asm)]

#[macro_use]
extern crate nix as ioctl_crate;
extern crate failure;
extern crate libc;
extern crate sgx_isa as abi;
extern crate sgxs as sgxs_crate;
#[macro_use]
extern crate failure_derive;

mod generic;
pub mod isgx;

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
