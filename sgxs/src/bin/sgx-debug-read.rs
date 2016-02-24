/*
 * Read SGX memory from debug enclaves
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

extern crate sgxs as sgxs_crate;

use std::io::{Write,stdout,stderr};

use sgxs_crate::sgxdev;

fn main() {
	let dev=sgxdev::Device::open("/dev/sgx").unwrap();

	let mut args=std::env::args();
	let _=args.next();
	let addr=args.next().and_then(|v|u64::from_str_radix(&v,16).ok()).expect("Usage: sgxs-sim <start_offset_hex> <num_qwords_hex>");
	let num=args.next().and_then(|v|usize::from_str_radix(&v,16).ok()).expect("Usage: sgxs-sim <start_offset_hex> <num_qwords_hex>");

	let (mem,errors)=dev.debug_read(addr,num).unwrap();
	if errors.len()>0 {
		writeln!(stderr(),"Errors reading the following addresses:").unwrap();
		for (i,error) in errors.into_iter().enumerate() {
			write!(stderr(),"0x{:016x} ",error).unwrap();
			if i%4 == 3 {
				writeln!(stderr(),"").unwrap();
			}
		}
	}
	stdout().write_all(unsafe{std::slice::from_raw_parts(mem.as_ptr() as *const u8,mem.len()*8)}).unwrap();
}
