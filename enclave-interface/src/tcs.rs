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

use sgxs::loader::Address;
use sgx_isa::Enclu;

#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn handle_usercall(p1: u64, p2: u64, p3: u64, closure: *mut &mut FnMut(u64,u64,u64,u64,u64) -> u64, p4: u64, p5: u64) -> u64 {
	(*closure)(p1,p2,p3,p4,p5)
}

pub fn enter<T: FnMut(u64,u64,u64,u64,u64) -> u64>(tcs: Address, mut on_usercall: T, p1: u64, p2: u64, p3: u64, p4: u64, p5: u64) -> u64 {
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
		: "{r12}"(u64::from(tcs)), "{r10}"(debug_buf.as_ptr()), "{r13}"(&mut (&mut on_usercall as &mut FnMut(u64,u64,u64,u64,u64) -> u64))
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

/*
fn main() {
	let matches = App::new("sgxs-load")
		.about("SGXS loader")
		.arg(Arg::with_name("debug").short("d").long("debug").requires("le-sgxs").help("Request a debug token"))
		.arg(Arg::with_name("le-sgxs").long("le-sgxs").takes_value(true).requires("le-sigstruct").help("Sets the launch enclave SGXS file to use"))
		.arg(Arg::with_name("le-sigstruct").long("le-sigstruct").takes_value(true).requires("le-sgxs").help("Sets the launch enclave SIGSTRUCT file to use"))
		.arg(Arg::with_name("token").long("token").takes_value(true).help("Sets the enclave EINITTOKEN file to use"))
		.arg(Arg::with_name("device").long("device").takes_value(true).help("Sets the SGX device to use (default: /dev/sgx)"))
		.arg(Arg::with_name("sgxs").required(true).help("Sets the enclave SGXS file to use"))
		.arg(Arg::with_name("sigstruct").required(true).help("Sets the enclave SIGSTRUCT file to use"))
		.after_help("LAUNCH ENCLAVE / TOKEN OPTION:
	When specifying <token>, but no <le-...>, that token file will be used as
	EINITTOKEN. When specifying <le-...>, but not <token>, the launch enclave
	will be used to generate an EINITTOKEN. When specifying <le-...> and
	<token>, that token file will be used as EINITTOKEN. If loading with that
	token fails, the launch enclave will be used to generate an EINITTOKEN, and
	the new token will be written back to <token>.")
		.get_matches();

	let dev=isgx::Device::open(matches.value_of("device").unwrap_or("/dev/isgx")).unwrap();
	let mut file=File::open(matches.value_of("sgxs").unwrap()).unwrap();
	let sigstruct=read_sigstruct(matches.value_of("sigstruct").unwrap());
	let use_le=matches.is_present("le-sgxs");
	let mapping;
	let mut token=None;
	{
		use sgxs::loader::OptionalEinittoken as OptTok;
		let token_opt;
		match matches.value_of("token") {
			Some(path) => {
				let mut intoken=read_einittoken(path);
				if matches.is_present("debug") && intoken.valid==0 {
					intoken.attributes=sigstruct.attributes.clone();
					intoken.attributes.flags.insert(ATTRIBUTE_DEBUG);
				}
				token=Some(intoken);
				if use_le {
					token_opt=OptTok::UseOrGenerate(token.as_mut().unwrap())
				} else {
					token_opt=OptTok::Use(token.as_ref().unwrap())
				}
			},
			None => {
				if matches.is_present("debug") {
					let mut attributes=sigstruct.attributes.clone();
					attributes.flags.insert(ATTRIBUTE_DEBUG);
					token_opt=OptTok::None(Some(attributes))
				} else {
					token_opt=OptTok::None(None)
				}
			}
		}
		if use_le {
			let mut le=File::open(matches.value_of("le-sgxs").unwrap()).unwrap();
			let le_sig=read_sigstruct(matches.value_of("le-sigstruct").unwrap());
			mapping=dev.load_with_launch_enclave(&mut file,&sigstruct,token_opt,&mut le,&le_sig).unwrap();
		} else {
			mapping=dev.load(&mut file,&sigstruct,token_opt.as_option()).unwrap();
		}
	}
	if let Some(token)=token {
		if use_le {
			write_einittoken(matches.value_of("token").unwrap(),token);
		}
	}

	let tcs=mapping.tcss()[0];
	let mut user_heap: *mut libc::c_void=std::ptr::null_mut();
	let user_heap_size=16*1024*1024;
	unsafe{libc::posix_memalign(&mut user_heap,4096,user_heap_size)};
	assert!(user_heap!=std::ptr::null_mut());
	&*REDIS_SOCK;
	&*TPM_FILE;
	let start=std::time::Instant::now();
	println!("Enclave returned {:x}",enclave_call(tcs,user_heap as u64,user_heap_size as u64,0,0,0));
	println!("{:?}",start.elapsed());
}
*/
