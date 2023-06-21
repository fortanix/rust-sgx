/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod alloc;

extern crate zeroize;
use zeroize::Zeroize;

#[no_mangle]
/// Rust version of [`explicit_bzero`], implemented by using [`zeroize::Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html)
pub unsafe extern "C" fn explicit_bzero(buf: *mut std::ffi::c_void, len: alloc::size_t)  {
    let buffer = core::slice::from_raw_parts_mut(buf as *mut std::ffi::c_char, len);
    buffer.zeroize();
}