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

use std::iter;
use std::mem::forget as mem_forget;
use std::slice::from_raw_parts_mut;

use spin::Mutex;
use alloc_buddy_simple::{FreeBlock,Heap};
use mem;

#[cfg(feature="allocator")]
pub fn init() {
	use alloc_buddy_simple::initialize_allocator;

	static mut FREE_LISTS: &'static mut [*mut FreeBlock] = &mut [0 as *mut _; 14];

	extern {
		static HEAP_BASE: u64;
		static HEAP_SIZE: usize;
	}

	unsafe{initialize_allocator(mem::rel_ptr_mut(HEAP_BASE), HEAP_SIZE, FREE_LISTS)};

	::rustc_alloc::oom::set_oom_handler(oom_handler);
}
#[cfg(not(feature="allocator"))]
pub fn init() {
	panic!("Initializing allocator without enabling it.")
}

#[cfg(all(feature="allocator",test))]
const E:RUN_TEST_WITH_NO_DEFAULT_FEATURES=();

#[cfg(feature="debug")]
fn oom_handler() -> ! {
	::panic::debug::panic_msg("Out of heap memory!");
}
#[cfg(not(feature="debug"))]
fn oom_handler() -> ! {
	unsafe{::panic::panic_exit()};
}

// from alloc_buddy_simple::math
fn log2(mut temp: usize) -> u8 {
	let mut result = 0;
	temp >>= 1;
	while temp != 0 {
		result += 1;
		temp >>= 1;
	}
	result
}

pub static USER_HEAP: Mutex<Option<Heap<'static>>> = Mutex::new(None);

pub fn init_user(heap_base: *mut u8, heap_size: usize)
{
	assert!(mem::is_user_range(heap_base,heap_size));
	let mut heap = USER_HEAP.lock();
	if heap.is_none() {
		unsafe {
			let len=(log2(heap_size/8)-1) as usize;
			let mut free_lists=iter::repeat(0 as *mut FreeBlock).take(len).collect::<Vec<_>>();
			let ptr=free_lists.as_mut_ptr();
			mem_forget(free_lists);
			*heap = Some(Heap::new(heap_base, heap_size, from_raw_parts_mut(ptr,len)));
		}
	}
}
