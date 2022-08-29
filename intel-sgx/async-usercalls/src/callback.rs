use fortanix_sgx_abi::{invoke_with_usercalls, Fd, Result};
use std::io;
use std::os::fortanix_sgx::usercalls::raw::{Return, ReturnValue};
use std::os::fortanix_sgx::usercalls::FromSgxResult;

pub struct CbFn<T>(Box<dyn FnOnce(T) + Send + 'static>);

impl<T> CbFn<T> {
    fn call(self, t: T) {
        (self.0)(t);
    }
}

impl<F, T> From<F> for CbFn<T>
where
    F: FnOnce(T) + Send + 'static,
{
    fn from(f: F) -> Self {
        Self(Box::new(f))
    }
}

macro_rules! cbfn_type {
    ( )                      => { CbFn<()> };
    ( -> ! )                 => { () };
    ( -> u64 )               => { CbFn<u64> };
    ( -> (Result, usize) )   => { CbFn<io::Result<usize>> };
    ( -> (Result, u64) )     => { CbFn<io::Result<u64>> };
    ( -> (Result, Fd) )      => { CbFn<io::Result<Fd>> };
    ( -> (Result, *mut u8) ) => { CbFn<io::Result<*mut u8>> };
    ( -> Result )            => { CbFn<io::Result<()>> };
}

macro_rules! call_cbfn {
    ( $cb:ident, $rv:expr, )          => { let x: () = $rv; $cb.call(x); };
    ( $cb:ident, $rv:expr, -> ! )     => { let _: ! = $rv; };
    ( $cb:ident, $rv:expr, -> u64 )   => { let x: u64 = $rv; $cb.call(x); };
    ( $cb:ident, $rv:expr, -> $t:ty ) => { let x: $t = $rv; $cb.call(x.from_sgx_result()); };
}

macro_rules! define_callback {
    ($(fn $name:ident($($n:ident: $t:ty),*) $(-> $r:tt)*; )*) => {
        #[allow(unused)]
        #[allow(non_camel_case_types)]
        pub(crate) enum Callback {
            $( $name(cbfn_type! { $(-> $r)* }), )*
        }

        impl Callback {
            pub(crate) fn call(self, ret: Return) {
                match self {$(
                    Callback::$name(_cb) => {
                        call_cbfn!(
                            _cb,
                            ReturnValue::from_registers(stringify!($name), (ret.0, ret.1)),
                            $(-> $r)*
                        );
                    }
                )*}
            }
        }
    };
}

invoke_with_usercalls!(define_callback);
