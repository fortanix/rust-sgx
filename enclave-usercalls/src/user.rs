/// Use the `define_usercalls!` macro to define a common interface between
/// enclave and userspace. Inside the macro, you should list one or more
/// function signatures:
///
/// ```rust,no_run
/// #[macro_use]
/// extern crate enclave_usercalls;
///
/// define_usercalls! {
/// 	fn print(message: *const u8, message_len: usize);
/// }
/// ```
///
/// Each function must have between 0 and 4 arguments. The arguments and the
/// return value must implement [`RegisterArgument`](trait.RegisterArgument.html).
///
/// In an enclave, this will result in the following definitions which will
/// call `enclave::usercall:do_usercall` appropriately:
///
/// ```ignore
/// pub unsafe fn print(message: *const u8, message_len: usize) {
/// 	...
/// }
/// ```
///
/// In userspace, this will result in the following trait and function
/// definition:
///
/// ```ignore
/// pub trait Usercalls {
/// 	unsafe fn print(message: *const u8, message_len: usize);
/// }
/// pub fn dispatch<H: Usercalls>(n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
/// 	...
/// }
/// ```
///
/// The trait must be implemented by the usercall handler. The `dispatch`
/// function can be passed directly to `enclave_interface::tcs::enter`.
#[macro_export]
macro_rules! define_usercalls {
	($( fn $f:ident($($n:ident: $t:ty),*) $(-> $r:ty)*; )*) => (
		use $crate::{Register,RegisterArgument as RA};

		#[repr(C)]
		#[allow(non_camel_case_types)]
		enum UsercallList {
			__enclave_usercalls_invalid,
			$($f,)*
		}
		pub trait Usercalls {
			$(unsafe fn $f(&mut self, $($n: $t),*) $(-> $r)*;)*
		}

		pub const USERCALL_YIELD: u64 = 0x7fff_ffff_ffff_ffff;

		#[allow(unused_variables)]
		pub fn dispatch<H: Usercalls>(handler: &mut H, n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
			// using if/else because you can't match an integer against enum variants
			$(
				if n == UsercallList::$f as Register {
					RA::into_register(unsafe{enclave_usercalls_internal_define_usercalls!(handler, replace_args a1,a2,a3,a4 $f($($n),*))})
				} else
			)*
			if n == USERCALL_YIELD {
				return RA::into_register(());
			} else {
				panic!("Invalid usercall {}",n);
			}
		}
	);
}
#[macro_export]
#[doc(hidden)]
macro_rules! enclave_usercalls_internal_define_usercalls {
	($h:ident, replace_args $a1:ident,$a2:ident,$a3:ident,$a4:ident $f:ident($n1:ident, $n2:ident, $n3:ident, $n4:ident)) => (
		H::$f(
			$h,
			RA::from_register($a1),
			RA::from_register($a2),
			RA::from_register($a3),
			RA::from_register($a4),
		)
	);
	($h:ident, replace_args $a1:ident,$a2:ident,$a3:ident,$a4:ident $f:ident($n1:ident, $n2:ident, $n3:ident)) => (
		H::$f(
			$h,
			RA::from_register($a1),
			RA::from_register($a2),
			RA::from_register($a3),
		)
	);
	($h:ident, replace_args $a1:ident,$a2:ident,$a3:ident,$a4:ident $f:ident($n1:ident, $n2:ident)) => (
		H::$f(
			$h,
			RA::from_register($a1),
			RA::from_register($a2),
		)
	);
	($h:ident, replace_args $a1:ident,$a2:ident,$a3:ident,$a4:ident $f:ident($n1:ident)) => (
		H::$f(
			$h,
			RA::from_register($a1),
		)
	);
	($h:ident, replace_args $a1:ident,$a2:ident,$a3:ident,$a4:ident $f:ident()) => (
		H::$f($h)
	);
}
