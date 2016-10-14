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
	use std::fmt::{self,Write};
	use super::panic_exit;

	struct DebugMsgBuf {
		slice: &'static mut [u8],
		ind: usize,
	}

	impl fmt::Write for DebugMsgBuf {
		fn write_str(&mut self, s: &str) -> fmt::Result {
			let src=s.as_bytes();
			let dst=&mut self.slice[self.ind..];
			let len=::std::cmp::min(dst.len(),src.len());
			(&mut dst[..len]).clone_from_slice(&src[..len]);
			self.ind+=len;
			Ok(())
		}
	}

	impl DebugMsgBuf {
		fn new() -> DebugMsgBuf {
			extern "C" { fn get_debug_panic_buf_ptr() -> *mut u8; }

			let mut buf=unsafe{::std::slice::from_raw_parts_mut(get_debug_panic_buf_ptr(),1024)};
			DebugMsgBuf{slice:buf,ind:0}
		}
	}

	#[no_mangle]
	pub extern "C" fn panic_msg(msg: &str) -> ! {
		let _=DebugMsgBuf::new().write_str(msg);
		unsafe{panic_exit();}
	}

	pub fn init() {
		::std::panic::set_hook(Box::new(|info|{
			let msg = match info.payload().downcast_ref::<&'static str>() {
				Some(s) => *s,
				None => match info.payload().downcast_ref::<String>() {
					Some(s) => &s,
					None => "unknown panic payload",
				}
			};

			if let Some(loc) = info.location() {
				let _=write!(DebugMsgBuf::new(),"'{}' at {}:{}", msg, loc.file(), loc.line());
				unsafe{panic_exit()}
			} else {
				panic_msg(msg)
			}
		}));
	}
}

#[cfg(feature="debug")]
pub use self::debug::init;

#[cfg(not(feature="debug"))]
pub fn init() {
	::std::panic::set_hook(Box::new(|_|unsafe{panic_exit()}));
}

extern "C" { pub fn panic_exit() -> !; }
