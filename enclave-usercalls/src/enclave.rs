extern crate enclave as libenclave;
pub use self::libenclave::usercall::do_usercall;

/// See `user::define_usercalls!` for macro documentation
#[macro_export]
macro_rules! define_usercalls {
	($( fn $f:ident($($n:ident: $t:ty),*) $(-> $r:ty)*; )*) => (
		use $crate::{Register,RegisterArgument as RA};
		use $crate::enclave::do_usercall;

		#[repr(C)]
		enum Usercalls {
			__enclave_usercalls_invalid,
			$($f,)*
		}
		$(enclave_usercalls_internal_define_usercalls!(def fn $f($($n: $t),*) $(-> $r)*);)*
	);
}
#[macro_export]
#[doc(hidden)]
macro_rules! enclave_usercalls_internal_define_usercalls {
	(def fn $f:ident($n1:ident: $t1:ty, $n2:ident: $t2:ty, $n3:ident: $t3:ty, $n4:ident: $t4:ty) -> $r:ty) => (
		#[inline(always)]
		pub unsafe fn $f($n1: $t1, $n2: $t2, $n3: $t3, $n4: $t4) -> $r {
			RA::from_register(do_usercall(
				Usercalls::$f as Register,
				RA::into_register($n1),
				RA::into_register($n2),
				RA::into_register($n3),
				RA::into_register($n4),
			))
		}
	);
	(def fn $f:ident($n1:ident: $t1:ty, $n2:ident: $t2:ty, $n3:ident: $t3:ty) -> $r:ty) => (
		#[inline(always)]
		pub unsafe fn $f($n1: $t1, $n2: $t2, $n3: $t3) -> $r {
			RA::from_register(do_usercall(
				Usercalls::$f as Register,
				RA::into_register($n1),
				RA::into_register($n2),
				RA::into_register($n3),
				0
			))
		}
	);
	(def fn $f:ident($n1:ident: $t1:ty, $n2:ident: $t2:ty) -> $r:ty) => (
		#[inline(always)]
		pub unsafe fn $f($n1: $t1, $n2: $t2) -> $r {
			RA::from_register(do_usercall(
				Usercalls::$f as Register,
				RA::into_register($n1),
				RA::into_register($n2),
				0,0
			))
		}
	);
	(def fn $f:ident($n1:ident: $t1:ty) -> $r:ty) => (
		#[inline(always)]
		pub unsafe fn $f($n1: $t1) -> $r {
			RA::from_register(do_usercall(
				Usercalls::$f as Register,
				RA::into_register($n1),
				0,0,0
			))
		}
	);
	(def fn $f:ident() -> $r:ty) => (
		#[inline(always)]
		pub unsafe fn $f() -> $r {
			RA::from_register(do_usercall(
				Usercalls::$f as Register,
				0,0,0,0
			))
		}
	);
	(def fn $f:ident($($n:ident: $t:ty),*)) => (
		enclave_usercalls_internal_define_usercalls!(def fn $f($($n: $t),*) -> ());
	);
}
