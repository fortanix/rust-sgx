/*
 * Example secure enclave written in Rust
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

#![no_main]

extern crate enclave;
extern crate enclave_example_usercalls;

use enclave::usercall::UserSlice;

#[no_mangle]
pub extern "C" fn entry(user_heap_ptr: u64, user_heap_size: u64, _p3: u64, _ignore: u64, _p4: u64, _p5: u64) -> u64 {
	enclave::usercall::init_user_heap(user_heap_ptr as _,user_heap_size as _);

	let user_msg=UserSlice::clone_from("Hello world from inside SGX!".as_bytes());
	unsafe{enclave_example_usercalls::print(user_msg.as_ptr(),user_msg.len())};
	return 1234;
}
