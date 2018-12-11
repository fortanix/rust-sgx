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

pub mod isgx;
