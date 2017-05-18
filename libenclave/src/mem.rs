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

// Do not remove inline: will result in relocation failure
#[inline(always)]
pub unsafe fn rel_ptr<T>(offset: u64) -> *const T {
	(image_base()+offset) as *const T
}

// Do not remove inline: will result in relocation failure
#[inline(always)]
pub unsafe fn rel_ptr_mut<T>(offset: u64) -> *mut T {
	(image_base()+offset) as *mut T
}

extern {
	static ENCLAVE_SIZE: usize;
}

// Do not remove inline: will result in relocation failure
// For the same reason we use inline ASM here instead of an extern static to
// locate the base
#[inline(always)]
fn image_base() -> u64 {
	let base;
	unsafe{asm!("lea IMAGE_BASE(%rip),$0":"=r"(base))};
	base
}

pub fn is_enclave_range(p: *const u8, len: usize) -> bool {
	let start=p as u64;
	let end=start+(len as u64);
	start >= image_base() && end <= image_base()+(unsafe{ENCLAVE_SIZE} as u64) // unsafe ok: link-time constant
}

pub fn is_user_range(p: *const u8, len: usize) -> bool {
	let start=p as u64;
	let end=start+(len as u64);
	end <= image_base() || start >= image_base()+(unsafe{ENCLAVE_SIZE} as u64) // unsafe ok: link-time constant
}
