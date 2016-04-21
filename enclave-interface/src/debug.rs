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

use libc;

use std::sync::{RwLock,RwLockReadGuard};
use std::io::{stdout,stdin,Read,Write,Error as IoError,ErrorKind as IoErrorKind};

use sgxs::loader::Address;
use sgx_isa::Enclu;

lazy_static! {
	static ref SIGNAL_HANDLER: RwLock<Option<SignalHandler>> = RwLock::new(None);
}

struct SignalHandler {
	old_handler: libc::sighandler_t,
	in_segv: bool,
	buf: [u64;512],
	tcs: Address,
}

extern "C" fn segv_handler() -> ! {
	{
		let mut lock=SIGNAL_HANDLER.write().unwrap();
		let handler=lock.as_mut().unwrap();
		println!("Segmentation fault. Debug mode activated.");
		if handler.in_segv {
			panic!("Double segfault!")
		}
		handler.in_segv=true;
	}
	let lock=SIGNAL_HANDLER.read().unwrap();
	let handler=lock.as_ref().unwrap();
	loop {
		let mut instr=String::new();

		println!("TCS={:x}, read addr?",u64::from(handler.tcs));
		print!("0x");
		stdout().flush().unwrap();
		stdin().read_line(&mut instr).unwrap();
		instr.pop();
		let inaddr=u64::from_str_radix(&instr,16).unwrap();
		let result: u32;

		unsafe {
			asm!("
			lea 1f(%rip),%rcx
1:
			enclu
"			: "={eax}"(result)
			: "{eax}"(Enclu::EEnter), "{rbx}"(u64::from(handler.tcs)), "{rdi}"(handler.buf.as_ptr()), "{rsi}"(inaddr)
			: "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory"
			: "volatile"
		)};

		if result!=(Enclu::EExit as u32) {
			panic!("Invalid return value in EAX! eax={}",result);
		}

		for (n,vals) in handler.buf.chunks(4).enumerate() {
			println!("{:03x} {:016x} {:016x} {:016x} {:016x}",n*4*8,vals[0],vals[1],vals[2],vals[3]);
		}
	}
}

pub struct InstalledSignalHandler {
	lock: Option<RwLockReadGuard<'static,Option<SignalHandler>>>,
}

impl Drop for InstalledSignalHandler {
	fn drop(&mut self) {
		drop(self.lock.take().unwrap());
		let mut lock=SIGNAL_HANDLER.write().unwrap();
		let handler=lock.take().unwrap();
		unsafe{libc::signal(libc::SIGSEGV,handler.old_handler)};
	}
}

/// Install a custom SIGSEGV handler that can communicate with the enclave if
/// it was compiled with debugging features enabled.
///
/// Will block if a handler is already installed.
///
/// The handler will be uninstalled if the returned value is dropped.
pub fn install_segv_signal_handler(tcs: Address) -> Result<InstalledSignalHandler,IoError> {
	let mut lock=SIGNAL_HANDLER.write().unwrap();
	if lock.is_some() {
		return Err(IoError::new(IoErrorKind::AlreadyExists,"A signal handler is already installed"));
	}
	match unsafe{libc::signal(libc::SIGSEGV,segv_handler as *const () as libc::sighandler_t)} {
		libc::SIG_ERR => Err(IoError::last_os_error()),
		h @ _ => {
			*lock=Some(SignalHandler{
				old_handler:h,
				in_segv:false,
				buf:[0;512],
				tcs:tcs,
			});
			drop(lock);
			Ok(InstalledSignalHandler{lock:Some(SIGNAL_HANDLER.read().unwrap())})
		},
	}
}
