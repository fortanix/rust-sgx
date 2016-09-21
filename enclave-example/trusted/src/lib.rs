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

#![no_std]
#![no_main]

extern crate enclave;

#[no_mangle]
pub extern "C" fn entry(p1: u64, p2: u64, p3: u64, _ignore: u64, p4: u64, p5: u64) -> u64 {
	return unsafe{enclave::usercall::do_usercall(p1+1,p2+1,p3+1,p4+1,p5+1)};
}

