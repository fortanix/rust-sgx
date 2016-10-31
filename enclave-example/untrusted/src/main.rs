/*
 * Example program using a secure enclave
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

extern crate sgxs;
extern crate sgx_isa;
extern crate enclave_interface;
extern crate enclave_example_usercalls;
extern crate libc;

use sgx_isa::Sigstruct;
use std::fs::File;
use std::io::{Error as IoError,self};

fn next_arg(args: &mut std::env::ArgsOs) -> Result<std::ffi::OsString,IoError> {
	args.next().ok_or(IoError::new(io::ErrorKind::InvalidInput,"missing argument"))
}

fn parse_args() -> Result<(File,Sigstruct,File,Sigstruct),(&'static str,IoError)> {
	use enclave_interface::util::read_sigstruct;

	let mut args=std::env::args_os();
	args.next(); // skip arg[0]
	let file=try!(next_arg(&mut args).and_then(File::open).map_err(|err|("file",err)));
	let sig=try!(next_arg(&mut args).and_then(File::open).and_then(|mut f|read_sigstruct(&mut f)).map_err(|err|("sig",err)));
	let le_file=try!(next_arg(&mut args).and_then(File::open).map_err(|err|("le_file",err)));
	let le_sig=try!(next_arg(&mut args).and_then(File::open).and_then(|mut f|read_sigstruct(&mut f)).map_err(|err|("le_sig",err)));
	Ok((file,sig,le_file,le_sig))
}

struct Handler;

impl enclave_example_usercalls::Usercalls for Handler {
	unsafe fn print(msg: *const u8, len: usize) {
		println!("Enclave: {}",std::str::from_utf8(std::slice::from_raw_parts(msg,len)).unwrap());
	}
}

fn main() {
	use sgxs::loader::{Load,Map,OptionalEinittoken as OptTok};
	use enclave_interface::tcs;

	let (mut file,sig,mut le_file,le_sig)=match parse_args() {
		Ok(res) => res,
		Err((arg,err)) => {
			println!("Usage: enclave-runner <file> <sig> <le_file> <le_sig>");
			println!("\nError with argument `{}': {}",arg,err);
			std::process::exit(1);
		}
	};

	let user_heap_size=16*1024*1024;
	let mut user_heap: *mut libc::c_void=std::ptr::null_mut();
	unsafe{libc::posix_memalign(&mut user_heap,4096,user_heap_size)};
	let user_heap=user_heap as _;

	let dev=sgxs::isgx::Device::open("/dev/sgx").unwrap();
	let mut mapping=dev.load_with_launch_enclave(&mut file,&sig,OptTok::None(None),&mut le_file,&le_sig).unwrap();

	let h=enclave_interface::debug::install_segv_signal_handler(&mut mapping.tcss()[0]);
	let ret=tcs::enter(&mut mapping.tcss()[0],enclave_example_usercalls::dispatch::<Handler>,user_heap,user_heap_size as _,0,0,0);
	drop(h);

	println!("Enclave returned: {}",ret);
}
