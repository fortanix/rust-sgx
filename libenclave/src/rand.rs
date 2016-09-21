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

pub fn rand() -> u64 {
	let ret;
	let mut retry=10;
	unsafe{asm!("
1:
		rdrand $0
		jc 2f
		dec $1
		jnz 1b
2:
	":"=r"(ret),"=r"(retry):"1"(retry)::"volatile")};
	if retry==0 { panic!("RDRAND failure") }
	ret
}
