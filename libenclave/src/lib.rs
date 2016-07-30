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

#![feature(linkage,lang_items,unwind_attributes,asm,const_fn,collections,unicode,alloc,oom,heap_api)]
#![no_std]

#[macro_use] extern crate collections;
extern crate rustc_unicode;
extern crate alloc as rustc_alloc;
extern crate sgx_isa;
#[cfg(not(test))] pub extern crate core_io as io;

extern crate spin;
extern crate rlibc;
extern crate alloc_buddy_simple;
#[macro_use] extern crate bitflags;

// runtime features
mod alloc;
mod reloc;
mod mem;
#[doc(hidden)] // pub/doc(hidden) because we refer to functions in assembly
pub mod panic;
#[doc(hidden)] // pub/doc(hidden) because we refer to functions in assembly
#[cfg(feature="debug")] pub mod debug;

// library features
pub mod usercall;
pub mod rand;
pub mod aes;
pub mod curve25519;
pub mod sgx;

#[doc(hidden)]
#[no_mangle]
#[cfg(not(test))]
pub unsafe extern "C" fn init() {
	reloc::relocate_elf_rela();
	alloc::init();
}
