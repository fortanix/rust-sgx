/*
 * The Rust secure enclave runtime and library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

#[no_mangle]
pub unsafe extern "C" fn debug_copy(dst: *mut u8, src: *const u8) {
	::std::ptr::copy_nonoverlapping(src,dst,0x1000);
}
