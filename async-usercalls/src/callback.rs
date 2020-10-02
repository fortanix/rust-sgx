use crate::duplicated::{FromSgxResult, ReturnValue};
use crate::hacks::Return;
use fortanix_sgx_abi::{Fd, Result as SxgResult};
use std::io;

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

pub(crate) enum Callback {
    Read(CbFn<io::Result<usize>>),
    Write(CbFn<io::Result<usize>>),
    Flush(CbFn<io::Result<()>>),
    Close(CbFn<()>),
    BindStream(CbFn<io::Result<Fd>>),
    AcceptStream(CbFn<io::Result<Fd>>),
    ConnectStream(CbFn<io::Result<Fd>>),
    InsecureTime(CbFn<u64>),
    Alloc(CbFn<io::Result<*mut u8>>),
    Free(CbFn<()>),
}

impl Callback {
    pub(crate) fn call(self, ret: Return) {
        use Callback::*;
        match self {
            Read(cb) => {
                let x: (SxgResult, usize) = ReturnValue::from_registers("read", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            Write(cb) => {
                let x: (SxgResult, usize) = ReturnValue::from_registers("write", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            Flush(cb) => {
                let x: SxgResult = ReturnValue::from_registers("flush", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            Close(cb) => {
                assert_eq!((ret.0, ret.1), (0, 0));
                cb.call(());
            }
            BindStream(cb) => {
                let x: (SxgResult, Fd) = ReturnValue::from_registers("bind_stream", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            AcceptStream(cb) => {
                let x: (SxgResult, Fd) = ReturnValue::from_registers("accept_stream", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            ConnectStream(cb) => {
                let x: (SxgResult, Fd) = ReturnValue::from_registers("connect_stream", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            InsecureTime(cb) => {
                let x: u64 = ReturnValue::from_registers("insecure_time", (ret.0, ret.1));
                cb.call(x);
            }
            Alloc(cb) => {
                let x: (SxgResult, *mut u8) = ReturnValue::from_registers("alloc", (ret.0, ret.1));
                let x = x.from_sgx_result();
                cb.call(x);
            }
            Free(cb) => {
                assert_eq!((ret.0, ret.1), (0, 0));
                cb.call(());
            }
        }
    }
}
