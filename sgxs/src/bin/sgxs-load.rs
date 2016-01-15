/*
 * SGXS loader utility.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#![feature(read_exact)]
#![feature(asm)]
extern crate sgxs;
extern crate libc;

use std::io::Read;
use std::fs::File;
use std::mem::transmute;

use sgxs::sgxdev;
use sgxs::abi::{Einittoken,Sigstruct,Enclu};

fn read_einittoken() -> Einittoken {
	let mut buf=[0u8;304];
	File::open("token").unwrap().read_exact(&mut buf).unwrap();
	unsafe{transmute(buf)}
}

fn read_sigstruct() -> Sigstruct {
	let mut buf=[0u8;1808];
	File::open("sig").unwrap().read_exact(&mut buf).unwrap();
	unsafe{transmute(buf)}
}

fn enclu_eenter(tcs: u64) {
	let result: u32;
	unsafe{asm!("
		lea aep(%rip),%rcx
		jmp enclu
aep:
		xor %eax,%eax
		jmp post
enclu:
		enclu
post:
"		: "={eax}"(result)
		: "{eax}"(Enclu::EEnter), "{rbx}"(tcs)
		: "rcx"
		: "volatile"
	)};

	if result==0 {
		println!("Got AEX");
	} else if result==(Enclu::EExit as u32) {
		println!("Got EEXIT");
	} else {
		panic!("Invalid return value in EAX! eax={}",result);
	}
}

fn main() {
	let dev=sgxdev::Device::open("/dev/sgx").unwrap();
	let mut file=File::open("sgxs").unwrap();
	let mapping=dev.load(&mut file,read_sigstruct(),Some(read_einittoken())).unwrap();
	let tcs=mapping.tcss()[0];

	enclu_eenter(tcs);
}
