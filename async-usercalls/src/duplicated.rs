//! this file contains code duplicated from libstd's sys/sgx
use fortanix_sgx_abi::{Error, Result, RESULT_SUCCESS};
use std::io;
use std::ptr::NonNull;

fn check_os_error(err: Result) -> i32 {
    // FIXME: not sure how to make sure all variants of Error are covered
    if err == Error::NotFound as _
        || err == Error::PermissionDenied as _
        || err == Error::ConnectionRefused as _
        || err == Error::ConnectionReset as _
        || err == Error::ConnectionAborted as _
        || err == Error::NotConnected as _
        || err == Error::AddrInUse as _
        || err == Error::AddrNotAvailable as _
        || err == Error::BrokenPipe as _
        || err == Error::AlreadyExists as _
        || err == Error::WouldBlock as _
        || err == Error::InvalidInput as _
        || err == Error::InvalidData as _
        || err == Error::TimedOut as _
        || err == Error::WriteZero as _
        || err == Error::Interrupted as _
        || err == Error::Other as _
        || err == Error::UnexpectedEof as _
        || ((Error::UserRangeStart as _)..=(Error::UserRangeEnd as _)).contains(&err)
    {
        err
    } else {
        panic!("Usercall: returned invalid error value {}", err)
    }
}

pub trait FromSgxResult {
    type Return;

    fn from_sgx_result(self) -> io::Result<Self::Return>;
}

impl<T> FromSgxResult for (Result, T) {
    type Return = T;

    fn from_sgx_result(self) -> io::Result<Self::Return> {
        if self.0 == RESULT_SUCCESS {
            Ok(self.1)
        } else {
            Err(io::Error::from_raw_os_error(check_os_error(self.0)))
        }
    }
}

impl FromSgxResult for Result {
    type Return = ();

    fn from_sgx_result(self) -> io::Result<Self::Return> {
        if self == RESULT_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(check_os_error(self)))
        }
    }
}

type Register = u64;

pub trait RegisterArgument {
    fn from_register(_: Register) -> Self;
    fn into_register(self) -> Register;
}

pub trait ReturnValue {
    fn from_registers(call: &'static str, regs: (Register, Register)) -> Self;
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

impl ReturnValue for ! {
    fn from_registers(call: &'static str, _regs: (Register, Register)) -> Self {
        panic!("Usercall {}: did not expect to be re-entered", call);
    }
}

impl ReturnValue for () {
    fn from_registers(_call: &'static str, usercall_retval: (Register, Register)) -> Self {
        assert!(usercall_retval.0 == 0);
        assert!(usercall_retval.1 == 0);
        ()
    }
}

impl<T: RegisterArgument> ReturnValue for T {
    fn from_registers(_call: &'static str, usercall_retval: (Register, Register)) -> Self {
        assert!(usercall_retval.1 == 0);
        T::from_register(usercall_retval.0)
    }
}

impl<T: RegisterArgument, U: RegisterArgument> ReturnValue for (T, U) {
    fn from_registers(_call: &'static str, regs: (Register, Register)) -> Self {
        (T::from_register(regs.0), U::from_register(regs.1))
    }
}
