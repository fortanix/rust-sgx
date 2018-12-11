/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! Trait-based usercall dispatching based on the ABI specification.
//!
//! The macros in this module implement a `trait Usercalls` and a `fn dispatch`
//! that together implement usercall handling according to the parsed ABI.

#![allow(unused)]

use fortanix_sgx_abi::*;

use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;

type Register = u64;

trait RegisterArgument {
    fn from_register(Register) -> Self;
    fn into_register(self) -> Register;
}

type EnclaveAbort = super::EnclaveAbort<bool>;

pub(crate) type UsercallResult<T> = ::std::result::Result<T, EnclaveAbort>;
pub(crate) type DispatchResult = UsercallResult<(Register, Register)>;

trait ReturnValue {
    fn into_registers(self) -> DispatchResult;
}

macro_rules! define_usercalls {
    // Using `$r:tt` because `$r:ty` doesn't match ! in `clobber_diverging`
    ($(fn $f:ident($($n:ident: $t:ty),*) $(-> $r:tt)*; )*) => {
        #[repr(C)]
        #[allow(non_camel_case_types)]
        enum UsercallList {
            __enclave_usercalls_invalid,
            $($f,)*
        }

        pub(crate) trait Usercalls {
            $(fn $f(&mut self, $($n: $t),*) -> dispatch_return_type!($(-> $r)*);)*

            fn other(&mut self, n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> DispatchResult {
                Err($crate::usercalls::EnclaveAbort::InvalidUsercall(n))
            }
        }

        #[allow(unused_variables)]
        pub(crate) fn dispatch<H: Usercalls>(handler: &mut H, n: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> DispatchResult {
            // using if/else because you can't match an integer against enum variants
            $(
                if n == UsercallList::$f as Register {
                    ReturnValue::into_registers(unsafe{enclave_usercalls_internal_define_usercalls!(handler, replace_args a1,a2,a3,a4 $f($($n),*))})
                } else
            )*
            {
                handler.other(n, a1, a2, a3, a4)
            }
        }
    };
}

macro_rules! define_ra {
    (< $i:ident > $t:ty) => {
        impl<$i> RegisterArgument for $t {
            fn from_register(a: Register) -> Self {
                a as _
            }
            fn into_register(self) -> Register {
                self as _
            }
        }
    };
    ($i:ty as $t:ty) => {
        impl RegisterArgument for $t {
            fn from_register(a: Register) -> Self {
                a as $i as _
            }
            fn into_register(self) -> Register {
                self as $i as _
            }
        }
    };
    ($t:ty) => {
        impl RegisterArgument for $t {
            fn from_register(a: Register) -> Self {
                a as _
            }
            fn into_register(self) -> Register {
                self as _
            }
        }
    };
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
    fn from_register(_: Register) -> () {
        ()
    }
    fn into_register(self) -> Register {
        0
    }
}

impl RegisterArgument for bool {
    fn from_register(a: Register) -> bool {
        if a != 0 {
            true
        } else {
            false
        }
    }
    fn into_register(self) -> Register {
        self as _
    }
}

impl<T: RegisterArgument> RegisterArgument for Option<NonNull<T>> {
    fn from_register(a: Register) -> Option<NonNull<T>> {
        NonNull::new(a as _)
    }
    fn into_register(self) -> Register {
        self.map_or(0 as _, NonNull::as_ptr) as _
    }
}

impl ReturnValue for EnclaveAbort {
    fn into_registers(self) -> DispatchResult {
        Err(self)
    }
}

impl<T: RegisterArgument> ReturnValue for UsercallResult<T> {
    fn into_registers(self) -> DispatchResult {
        self.map(|v| (v.into_register(), 0))
    }
}

impl<T: RegisterArgument, U: RegisterArgument> ReturnValue for UsercallResult<(T, U)> {
    fn into_registers(self) -> DispatchResult {
        self.map(|(a, b)| (a.into_register(), b.into_register()))
    }
}

macro_rules! dispatch_return_type {
    (-> !) => { EnclaveAbort };
    (-> $r:ty) => { UsercallResult<$r> };
    () => { UsercallResult<()> };
}

macro_rules! enclave_usercalls_internal_define_usercalls {
    (
        $h:ident,replace_args
        $a1:ident,
        $a2:ident,
        $a3:ident,
        $a4:ident
        $f:ident($n1:ident, $n2:ident, $n3:ident, $n4:ident)
    ) => {
        H::$f(
            $h,
            RegisterArgument::from_register($a1),
            RegisterArgument::from_register($a2),
            RegisterArgument::from_register($a3),
            RegisterArgument::from_register($a4),
        )
    };
    (
        $h:ident,replace_args
        $a1:ident,
        $a2:ident,
        $a3:ident,
        $a4:ident
        $f:ident($n1:ident, $n2:ident, $n3:ident)
    ) => {{
        assert_eq!(
            $a4,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "4th"
        );
        H::$f(
            $h,
            RegisterArgument::from_register($a1),
            RegisterArgument::from_register($a2),
            RegisterArgument::from_register($a3),
        )
    }};
    (
        $h:ident,replace_args
        $a1:ident,
        $a2:ident,
        $a3:ident,
        $a4:ident
        $f:ident($n1:ident, $n2:ident)
    ) => {{
        assert_eq!(
            $a3,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "3rd"
        );
        assert_eq!(
            $a4,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "4th"
        );
        H::$f(
            $h,
            RegisterArgument::from_register($a1),
            RegisterArgument::from_register($a2),
        )
    }};
    ($h:ident,replace_args $a1:ident, $a2:ident, $a3:ident, $a4:ident $f:ident($n1:ident)) => {{
        assert_eq!(
            $a2,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "2nd"
        );
        assert_eq!(
            $a3,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "3rd"
        );
        assert_eq!(
            $a4,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "4th"
        );
        H::$f($h, RegisterArgument::from_register($a1))
    }};
    ($h:ident,replace_args $a1:ident, $a2:ident, $a3:ident, $a4:ident $f:ident()) => {{
        assert_eq!(
            $a1,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "1st"
        );
        assert_eq!(
            $a2,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "2nd"
        );
        assert_eq!(
            $a3,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "3rd"
        );
        assert_eq!(
            $a4,
            0,
            "Usercall {}: expected {} argument to be 0",
            stringify!($f),
            "4th"
        );
        H::$f($h)
    }};
}

invoke_with_usercalls!(define_usercalls);
