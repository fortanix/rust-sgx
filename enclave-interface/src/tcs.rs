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

#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn handle_usercall(p1: u64, p2: u64, p3: u64, closure: *mut &mut FnMut(u64,u64,u64,u64,u64) -> u64, p4: u64, p5: u64) -> u64 {
	(*closure)(p1,p2,p3,p4,p5)
}

pub fn enter<T: FnMut(u64,u64,u64,u64,u64) -> u64>(tcs: &mut Tcs, mut on_usercall: T, p1: u64, p2: u64, p3: u64, p4: u64, p5: u64) -> u64 {
	let debug_buf=[0u8;1024];
	let sgx_result: u32;
	let retval: u64;
	let exit_mode: i64;

	unsafe{
		asm!("
1:
		mov %r12,%rbx
		mov $$2,%eax
		lea 2f(%rip),%rcx
2:
		enclu
		test %rdi,%rdi
		jle 3f
		mov %r13,%rcx
		call handle_usercall
		mov %rax,%rdx
		jmp 1b
3:
"		: "={eax}"(sgx_result), "={rdx}"(retval), "={rdi}"(exit_mode)
		: "{r12}"(u64::from(tcs.address())), "{r10}"(debug_buf.as_ptr()),
		  "{r13}"(&mut (&mut on_usercall as &mut FnMut(u64,u64,u64,u64,u64) -> u64)),
		  "{rdi}"(p1), "{rsi}"(p2), "{rdx}"(p3), "{r8}"(p4), "{r9}"(p5)
		: "rbx", "rcx", "r11", "memory"
		: "volatile"
	)};

	if sgx_result!=(Enclu::EExit as u32) {
		panic!("Invalid return value in EAX! eax={}",sgx_result);
	}
	if exit_mode<0 {
		let msg=match std::str::from_utf8(debug_buf.split(|v|*v==0).next().unwrap()) {
			Ok(s) => s,
			Err(_) => "(the error was not valid UTF-8)"
		};
		panic!("Enclave reported panic: {}",msg);
	}

	return retval;
}
