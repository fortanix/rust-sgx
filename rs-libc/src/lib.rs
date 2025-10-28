/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod alloc;

extern crate zeroize;
use zeroize::Zeroize;

/// Rust version of [`explicit_bzero`], implemented by using [`zeroize::Zeroize`](https://docs.rs/zeroize/latest/zeroize/trait.Zeroize.html)
#[no_mangle]
pub unsafe extern "C" fn explicit_bzero(buf: *mut std::ffi::c_void, len: alloc::size_t) {
    let buffer = core::slice::from_raw_parts_mut(buf as *mut std::ffi::c_char, len);
    buffer.zeroize();
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use super::*;

    #[test]
    fn test_explicit_bzero() {
        let mut buf = [1u8, 2, 3, 4, 5];
        let len = buf.len();

        // Call the unsafe C function
        unsafe {
            explicit_bzero(buf.as_mut_ptr() as *mut c_void, len as alloc::size_t);
        }

        // Check that the buffer has been zeroed out
        assert_eq!(&buf, &[0u8; 5]);
    }

    #[test]
    fn test_explicit_bzero_zero_buffer() {
        let mut buf = [0u8; 5];
        let len = buf.len();

        // Call the unsafe C function
        unsafe {
            explicit_bzero(buf.as_mut_ptr() as *mut c_void, len as alloc::size_t);
        }

        // Check that the buffer is still all zero
        assert_eq!(&buf, &[0u8; 5]);
    }
}
