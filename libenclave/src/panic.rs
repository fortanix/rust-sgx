/*
 * The Rust secure enclave runtime and library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

#[cfg(feature="debug")]
pub mod debug {
	use core::fmt::{self,Write};
	use super::panic_exit;

	struct DebugMsgBuf {
		slice: &'static mut [u8],
		ind: usize,
	}

	impl fmt::Write for DebugMsgBuf {
		fn write_str(&mut self, s: &str) -> fmt::Result {
			let src=s.as_bytes();
			let dst=&mut self.slice[self.ind..];
			let len=::core::cmp::min(dst.len(),src.len());
			(&mut dst[..len]).clone_from_slice(&src[..len]);
			self.ind+=len;
			Ok(())
		}
	}

	impl DebugMsgBuf {
		fn new() -> DebugMsgBuf {
			extern "C" { fn get_debug_panic_buf_ptr() -> *mut u8; }

			let mut buf=unsafe{::core::slice::from_raw_parts_mut(get_debug_panic_buf_ptr(),1024)};
			DebugMsgBuf{slice:buf,ind:0}
		}
	}

	#[lang = "panic_fmt"]
	#[unwind]
	#[cfg(not(test))]
	pub extern fn panic_fmt(msg: fmt::Arguments, file: &'static str, line: u32) -> ! {
		let mut bufp=DebugMsgBuf::new();
		let p=&bufp as *const _;
		let _=bufp.write_fmt(msg);
		let _=bufp.write_fmt(format_args!("\nRSP:{:p}\n{}:{}",p,file,line));
		unsafe{panic_exit();}
	}

	#[no_mangle]
	pub extern "C" fn panic_msg(msg: &'static str) -> ! {
		let _=DebugMsgBuf::new().write_str(msg);
		unsafe{panic_exit();}
	}
}

#[lang = "panic_fmt"]
#[unwind]
#[cfg(not(any(feature="debug",test)))]
pub extern fn panic_fmt() -> ! { unsafe{panic_exit();} }

#[no_mangle]
#[unwind]
#[allow(non_snake_case)]
#[cfg(not(test))]
pub extern fn _Unwind_Resume() -> ! { unsafe{panic_exit();} }

#[lang = "eh_personality"]
#[cfg(not(test))]
extern fn eh_personality() {}

extern "C" { pub fn panic_exit() -> !; }
