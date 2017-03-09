/*
 * Interface to interact with libenclave-based secure enclaves.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use std;

use sgxs::loader::Tcs;
use sgx_isa::Enclu;

pub fn enter<T: FnMut(u64,u64,u64,u64,u64) -> u64>(tcs: &mut Tcs, mut on_usercall: T, p1: u64, p2: u64, p3: u64, p4: u64, p5: u64) -> u64 {
	let mut result = coenter(tcs, p1, p2, p3, p4, p5);
	while let CoResult::Yield(usercall) = result {
		let (p1, p2, p3, p4, p5) = usercall.parameters();
		result = usercall.coreturn(on_usercall(p1, p2, p3, p4, p5));
	}
	match result {
		CoResult::Return(v) => v,
		CoResult::Yield(_) => unreachable!()
	}
}

#[derive(Debug)]
pub enum CoResult<Y, R> {
	Yield(Y),
	Return(R),
}

#[derive(Debug)]
pub struct Usercall<'tcs> {
	tcs: &'tcs mut Tcs,
	parameters: (u64,u64,u64,u64,u64)
}

pub type ThreadResult<'tcs> = CoResult<Usercall<'tcs>, u64>;

impl<'tcs> Usercall<'tcs> {
	pub fn parameters(&self) -> (u64,u64,u64,u64,u64) {
		self.parameters
	}

	pub fn coreturn(self, value: u64) -> ThreadResult<'tcs> {
		coenter(self.tcs, 0, 0, value, 0, 0)
	}
}

pub fn coenter<'tcs>(tcs: &'tcs mut Tcs, mut p1: u64, mut p2: u64, mut p3: u64, mut p4: u64, mut p5: u64) -> ThreadResult<'tcs> {
	let debug_buf=[0u8;1024];
	let sgx_result: u32;
	let mut _tmp: (u64, u64);

	unsafe{
		asm!("
		lea 1f(%rip),%rcx
1:
		enclu
"		: "={eax}"(sgx_result), "={rbx}"(_tmp.0), "={r10}"(_tmp.1),
		  "={rdi}"(p1), "={rsi}"(p2), "={rdx}"(p3), "={r8}"(p4), "={r9}"(p5)
		: "{eax}" (2), "{rbx}"(u64::from(tcs.address())), "{r10}"(debug_buf.as_ptr()),
		  "{rdi}"(p1), "{rsi}"(p2), "{rdx}"(p3), "{r8}"(p4), "{r9}"(p5)
		: "rcx", "r11", "memory"
		: "volatile"
	)};

	if sgx_result!=(Enclu::EExit as u32) {
		panic!("Invalid return value in EAX! eax={}",sgx_result);
	}
	if (p1 as i64)<0 {
		let msg=match std::str::from_utf8(debug_buf.split(|v|*v==0).next().unwrap()) {
			Ok(s) => s,
			Err(_) => "(the error was not valid UTF-8)"
		};
		panic!("Enclave reported panic: {}",msg);
	} else if p1>0 {
		CoResult::Yield(Usercall {
			tcs: tcs,
			parameters: (p1, p2, p3, p4, p5)
		})
	} else {
		CoResult::Return(p3)
	}
}
