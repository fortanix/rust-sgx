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

use core::slice::from_raw_parts;
use mem;

const R_X86_64_RELATIVE: u32 = 8;

#[repr(packed)]
struct Rela<T> {
	offset: T,
	info: T,
	addend: T,
}

pub fn relocate_elf_rela() {
	extern {
		static RELA: u64;
		static RELACOUNT: usize;
	}

	if RELACOUNT==0 { return }

	let relas=unsafe{from_raw_parts::<Rela<u64>>(mem::rel_ptr(RELA),RELACOUNT)};
	for rela in relas {
		if rela.info != (/*0 << 32 |*/R_X86_64_RELATIVE as u64) {
			panic!("Invalid relocation");
		}
		unsafe{*mem::rel_ptr_mut::<*const ()>(rela.offset)=mem::rel_ptr(rela.addend)};
	}
}
