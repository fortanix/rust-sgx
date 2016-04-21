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

use alloc;
use core::cell::UnsafeCell;
use core::mem::{size_of,align_of,transmute};
use core::ptr;
use core::raw::Slice;
use collections::Vec;

extern "C" { fn usercall(nr: u64, p1: u64, p2: u64, _ignore: u64, p3: u64, p4: u64) -> u64; }

pub unsafe fn do_usercall(nr: u64, p1: u64, p2: u64, p3: u64, p4: u64) -> u64 {
	if nr==0 || nr>=0x8000_0000_0000_0000 { panic!("Invalid usercall number {}",nr) }
	usercall(nr,p1,p2,0,p3,p4)
}

pub use alloc::init_user as init_user_heap;

pub struct UserBox<T: Copy>(*mut T);

impl<T: Copy> UserBox<T> {
	pub fn new(val: T) -> UserBox<T> {
		unsafe {
			let p=alloc::USER_HEAP.lock().as_mut().expect("Trying to allocate on unintialized heap")
				.allocate(size_of::<T>(),align_of::<T>()) as *mut T;
			assert!(p != ptr::null_mut());
			ptr::write(p,val);
			UserBox(p)
		}
	}

	pub unsafe fn as_ptr(&self) -> *const T {
		self.0 as *const T
	}

	pub fn to_enclave(&self) -> T {
		unsafe{ptr::read(self.0)}
	}
}

impl<T: Copy> Drop for UserBox<T> {
	fn drop(&mut self) {
		unsafe{alloc::USER_HEAP.lock().as_mut().unwrap()
			.deallocate(self.0 as *mut u8,size_of::<T>(),align_of::<T>())};
	}
}

pub struct UserSlice<T: Copy>(Slice<T>);

impl<T: Copy> UserSlice<T> {
	pub fn clone_from(val: &[T]) -> UserSlice<T> {
		let ret=Self::new_uninit(val.len());
		unsafe{ptr::copy(val.as_ptr(),ret.0.data as *mut T,val.len())};
		ret
	}

	pub fn new_uninit(len: usize) -> UserSlice<T> {
		unsafe {
			let p=alloc::USER_HEAP.lock().as_mut().expect("Trying to allocate on unintialized heap")
				.allocate(size_of::<T>()*len,align_of::<T>()) as *mut T;
			assert!(p != ptr::null_mut());
			UserSlice(Slice{data:p,len:len})
		}
	}

	fn as_unsafe_cell(&self) -> &UnsafeCell<[T]> {
		unsafe{transmute::<_,&UnsafeCell<[T]>>(self.0)}
	}

	pub unsafe fn as_ptr(&self) -> *const T {
		self.0.data
	}

	pub fn len(&self) -> usize {
		self.0.len
	}

	pub fn clone_into_enclave(&self,dst: &mut [T]) {
		assert!(dst.len()<=self.len());
		let len=::core::cmp::min(dst.len(),self.len());
		(&mut dst[..len]).clone_from_slice(&unsafe{&*self.as_unsafe_cell().get()}[..len]);
	}

	pub fn to_enclave_vec(&self) -> Vec<T> {
		unsafe{&*self.as_unsafe_cell().get()}.to_vec()
	}
}

impl<T: Copy> Drop for UserSlice<T> {
	fn drop(&mut self) {
		unsafe{alloc::USER_HEAP.lock().as_mut().unwrap()
			.deallocate(self.0.data as *mut u8,size_of::<T>()*self.0.len,align_of::<T>())};
	}
}
