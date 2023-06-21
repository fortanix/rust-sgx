/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::c_void;
use std::mem;
use std::ptr;

#[allow(non_camel_case_types)]
pub(crate) type size_t = usize;
const ALIGN: usize = 8;

// We purposefully mangle symbols, when compiling for test to avoid collision
// with libc.a
#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn malloc(size: size_t) -> *mut c_void {
    let ptr_size = mem::size_of::<*mut usize>();
    let alloc_size = size + ptr_size;
    let alloc_layout = Layout::from_size_align_unchecked(alloc_size, ALIGN);
    let ptr = System.alloc(alloc_layout) as *mut usize;
    if ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    ptr::write(ptr, alloc_size);
    ptr.offset(1) as *mut c_void
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn calloc(n: size_t, size: size_t) -> *mut c_void {
    let ptr_size = mem::size_of::<*mut usize>();
    let alloc_size = (n * size) + ptr_size;
    let alloc_layout = Layout::from_size_align_unchecked(alloc_size, ALIGN);
    let ptr = System.alloc_zeroed(alloc_layout) as *mut usize;
    if ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    ptr::write(ptr, alloc_size);
    ptr.offset(1) as *mut c_void
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    if ptr == ptr::null_mut() {
        return malloc(size);
    } else if size == 0 {
        free(ptr);
        return ptr::null_mut();
    }

    let ptr = (ptr as *mut usize).offset(-1);
    let ptr_size = mem::size_of::<*mut usize>();
    let old_alloc_layout = Layout::from_size_align_unchecked(ptr::read(ptr), ALIGN);
    let new_alloc_size = size + ptr_size;

    let ptr = System.realloc(ptr as _, old_alloc_layout, new_alloc_size) as *mut usize;
    if ptr == ptr::null_mut() {
        return ptr::null_mut();
    }

    ptr::write(ptr, new_alloc_size);
    ptr.offset(1) as *mut c_void
}

#[cfg_attr(not(test), no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr == ptr::null_mut() {
        return;
    }
    let ptr = (ptr as *mut usize).offset(-1);
    let alloc_layout = Layout::from_size_align_unchecked(ptr::read(ptr), ALIGN);
    System.dealloc(ptr as *mut u8, alloc_layout);
}

#[cfg(test)]
mod tests {

    // Below test verifies that from_size_align does not return an error.
    use super::ALIGN;
    use std::alloc::Layout;
    #[test]
    fn test_layout_unwrap() {
        let _ = Layout::from_size_align(1, ALIGN).unwrap();
        let _ = Layout::from_size_align(7, ALIGN).unwrap();
        let _ = Layout::from_size_align(1025, ALIGN).unwrap();
    }
}
