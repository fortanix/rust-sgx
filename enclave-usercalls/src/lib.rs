//! This crate is intended to be used in a small crate that is used both by the
//! enclave and the user code. Your crate will make a single call to
//! `define_usercalls!` to define a common interface between the enclave and
//! userspace. In an enclave, this interface will be presented as a bunch of
//! `pub unsafe fn`s. In userspace, there will be a `Usercalls` trait that your
//! usercall handler must implement.

#![no_std]

#[cfg(target_os="none")]
#[doc(hidden)]
pub mod enclave;
#[cfg(not(target_os="none"))]
mod user;

/// The type representing a full regular register on this platform.
pub type Register = u64;

/// A type that would be passed or returned in a regular register on this platform.
pub trait RegisterArgument {
	fn from_register(Register) -> Self;
	fn into_register(Self) -> Register;
}

macro_rules! define_ra {
	(<$i:ident> $t:ty) => (
		impl<$i> RegisterArgument for $t {
			fn from_register(a: Register) -> Self { a as _ }
			fn into_register(a: Self) -> Register { a as _ }
		}
	);
	($i:ty as $t:ty) => (
		impl RegisterArgument for $t {
			fn from_register(a: Register) -> Self { a as $i as _ }
			fn into_register(a: Self) -> Register { a as $i as _ }
		}
	);
	($t:ty) => (
		impl RegisterArgument for $t {
			fn from_register(a: Register) -> Self { a as _ }
			fn into_register(a: Self) -> Register { a as _ }
		}
	);
}

define_ra!(Register);
define_ra!(i64);
define_ra!(u32);
define_ra!(u32 as i32);
define_ra!(u16);
define_ra!(u16 as i16);
define_ra!(u8);
define_ra!(u8 as i8);
define_ra!(usize);
define_ra!(usize as isize);
define_ra!(<T> *const T);
define_ra!(<T> *mut T);

impl RegisterArgument for () {
	fn from_register(_: Register) -> () { () }
	fn into_register(_: ()) -> Register { 0 }
}

impl RegisterArgument for bool {
	fn from_register(a: Register) -> bool { if a!=0 { true } else { false } }
	fn into_register(a: bool) -> Register { a as _ }
}
