/*
 * SGXS loader utility.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![feature(asm)]
extern crate sgxs;
extern crate clap;
extern crate sgx_isa;

use std::io::{Write,Read};
use std::fs::File;
use std::mem::transmute;

use clap::{Arg,App};

use sgxs::loader::{Map,Load,Address};
use sgxs::isgx;
use sgx_isa::{Einittoken,Sigstruct,Enclu,attributes_flags};

fn read_einittoken(path: &str) -> Einittoken {
	let mut buf=[0u8;304];
	File::open(path).unwrap().read_exact(&mut buf).unwrap();
	unsafe{transmute(buf)}
}

fn write_einittoken(path: &str, token: Einittoken) {
	File::create(path).unwrap().write_all(&mut unsafe{transmute::<_,[u8;304]>(token)}).unwrap();
}

fn read_sigstruct(path: &str) -> Sigstruct {
	let mut buf=[0u8;1808];
	File::open(path).unwrap().read_exact(&mut buf).unwrap();
	unsafe{transmute(buf)}
}

fn enclu_eenter(tcs: Address) {
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
					intoken.attributes.flags.insert(attributes_flags::DEBUG);
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
					attributes.flags.insert(attributes_flags::DEBUG);
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
	enclu_eenter(tcs);
}
