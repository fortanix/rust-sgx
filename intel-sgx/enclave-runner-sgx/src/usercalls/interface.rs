/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! Adaptors between the usercall ABI types and functions and (mostly) safe
//! Rust types.

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::ops::{Deref, DerefMut};
use std::slice;

use fortanix_sgx_abi::*;

use super::abi::{UsercallResult, Usercalls};
use super::{EnclaveAbort, IOHandlerInput};
use futures::future::Future;
use futures::FutureExt;
use tokio::io::ReadBuf;

pub(super) struct Handler<'ioinput, 'tcs>(pub &'ioinput mut IOHandlerInput<'tcs>);

impl<'future, 'ioinput: 'future, 'tcs: 'ioinput> Usercalls<'future> for Handler<'ioinput, 'tcs> {
    fn is_exiting(&self) -> bool {
        self.0.is_exiting()
    }

    fn read(
        self,
        fd: Fd,
        buf: *mut u8,
        len: usize,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, usize)>)> + 'future>>
    {
        async move {
            unsafe {
                let ret = match from_raw_parts_mut_nonnull(buf, len) {
                    Ok(buf) => {
                        let mut buf = ReadBuf::new(buf);
                        self.0.read(fd, &mut buf).await.map(|_| buf.filled().len())
                    }
                    Err(e) => Err(e),
                };
                return (self, Ok(ret.to_sgx_result()));
            }
        }
        .boxed_local()
    }

    fn read_alloc(
        self,
        fd: Fd,
        buf: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<Result>)> + 'future>> {
        async move {
            unsafe {
                let ret;
                match buf.as_mut().ok_or(IoErrorKind::InvalidInput) {
                    Err(e) => ret = Err(e.into()),
                    Ok(k) => {
                        let mut out = OutputBuffer::new(k);
                        if !out.buf.data.is_null() {
                            ret = Err(IoErrorKind::InvalidInput.into());
                        } else {
                            ret = self.0.read_alloc(fd, &mut out).await;
                        }
                    }
                }
                return (self, Ok(ret.to_sgx_result()));
            }
        }
        .boxed_local()
    }

    fn write(
        self,
        fd: Fd,
        buf: *const u8,
        len: usize,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, usize)>)> + 'future>>
    {
        async move {
            unsafe {
                let ret = match from_raw_parts_nonnull(buf, len) {
                    Ok(buf) => self.0.write(fd, buf).await,
                    Err(e) => Err(e.into()),
                };
                return (self, Ok(ret.to_sgx_result()));
            }
        }
        .boxed_local()
    }

    fn flush(
        self,
        fd: Fd,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<Result>)> + 'future>> {
        async move {
            let ret = Ok(self.0.flush(fd).await.to_sgx_result());
            return (self, ret);
        }
        .boxed_local()
    }

    fn close(
        self,
        fd: Fd,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<()>)> + 'future>> {
        async move {
            let ret = Ok(self.0.close(fd).await);
            return (self, ret);
        }
        .boxed_local()
    }

    fn bind_stream(
        self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, Fd)>)> + 'future>>
    {
        async move {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                let ret = match from_raw_parts_nonnull(addr, len) {
                    Ok(addr) => self.0.bind_stream(addr, local_addr.as_mut()).await,
                    Err(e) => Err(e),
                };
                return (self, Ok(ret.to_sgx_result()));
            }
        }
        .boxed_local()
    }

    fn accept_stream(
        self,
        fd: Fd,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, Fd)>)> + 'future>>
    {
        async move {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                let mut peer_addr = peer_addr.as_mut().map(OutputBuffer::new);
                let ret = Ok(self
                    .0
                    .accept_stream(fd, local_addr.as_mut(), peer_addr.as_mut())
                    .await
                    .to_sgx_result());
                return (self, ret);
            }
        }
        .boxed_local()
    }

    fn connect_stream(
        self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, Fd)>)> + 'future>>
    {
        async move {
            unsafe {
                let mut local_addr = local_addr.as_mut().map(OutputBuffer::new);
                let mut peer_addr = peer_addr.as_mut().map(OutputBuffer::new);

                let ret = match from_raw_parts_nonnull(addr, len) {
                    Ok(addr) => {
                        self.0
                            .connect_stream(addr, local_addr.as_mut(), peer_addr.as_mut())
                            .await
                    }
                    Err(e) => Err(e.into()),
                };
                return (self, Ok(ret.to_sgx_result()));
            }
        }
        .boxed_local()
    }

    fn launch_thread(
        self,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<Result>)> + 'future>> {
        async move {
            let ret = Ok(self.0.launch_thread().to_sgx_result());
            return (self, ret);
        }
        .boxed_local()
    }

    fn exit(
        self,
        panic: bool,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, EnclaveAbort<bool>)> + 'future>> {
        async move {
            let ret = self.0.exit(panic);
            return (self, ret);
        }
        .boxed_local()
    }

    fn wait(
        self,
        event_mask: u64,
        timeout: u64,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, u64)>)> + 'future>>
    {
        async move {
            if event_mask == 0 && timeout == WAIT_INDEFINITE {
                return (self, Err(EnclaveAbort::IndefiniteWait));
            }

            let ret = Ok(self.0.wait(event_mask, timeout).await.to_sgx_result());
            return (self, ret);
        }
        .boxed_local()
    }

    fn send(
        self,
        event_set: u64,
        tcs: Option<Tcs>,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<Result>)> + 'future>> {
        async move {
            let ret = Ok(self.0.send(event_set, tcs).to_sgx_result());
            return (self, ret);
        }
        .boxed_local()
    }

    fn insecure_time(
        self,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = (Self, UsercallResult<(u64, *const InsecureTimeInfo)>)> + 'future>,
    > {
        async move {
            let ret = Ok(self.0.insecure_time());
            return (self, ret);
        }
        .boxed_local()
    }

    fn alloc(
        self,
        size: usize,
        alignment: usize,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<(Result, *mut u8)>)> + 'future>>
    {
        async move {
            let ret = Ok(self.0.alloc(size, alignment).to_sgx_result());
            return (self, ret);
        }
        .boxed_local()
    }

    fn free(
        self,
        ptr: *mut u8,
        size: usize,
        alignment: usize,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<()>)> + 'future>> {
        async move {
            let ret = Ok(self.0.free(ptr, size, alignment).unwrap());
            return (self, ret);
        }
        .boxed_local()
    }

    fn async_queues(
        self,
        usercall_queue: *mut FifoDescriptor<Usercall>,
        return_queue: *mut FifoDescriptor<Return>,
        cancel_queue: *mut FifoDescriptor<Cancel>,
    ) -> std::pin::Pin<Box<dyn Future<Output = (Self, UsercallResult<Result>)> + 'future>> {
        async move {
            unsafe {
                let ret = match (usercall_queue.as_mut(), return_queue.as_mut()) {
                    (Some(usercall_queue), Some(return_queue)) => self
                        .0
                        .async_queues(usercall_queue, return_queue, cancel_queue.as_mut())
                        .await
                        .map(Ok),
                    _ => Ok(Err(IoErrorKind::InvalidInput.into())),
                };
                return (self, ret.map(|v| v.to_sgx_result()));
            }
        }
        .boxed_local()
    }
}

// `T` could be more generic, we could take anything that can be turned into
// `Box<[u8]>`. However, `String`, which we definitely need, doesn't have a
// direct conversion.
pub(super) struct OutputBuffer<'a, T: Into<Vec<u8>>> {
    buf: &'a mut ByteBuffer,
    data: Option<T>,
}

impl<'a, T: Into<Vec<u8>>> OutputBuffer<'a, T> {
    fn new(buf: &'a mut ByteBuffer) -> Self {
        OutputBuffer { buf, data: None }
    }
}

impl<'a, T: Into<Vec<u8>> + Default> OutputBuffer<'a, T> {
    pub(super) fn init_default<'b>(&'b mut self) -> &'b mut T {
        self.data.get_or_insert_default()
    }
}

impl<'a, T: Into<Vec<u8>>> Deref for OutputBuffer<'a, T> {
    type Target = Option<T>;

    fn deref(&self) -> &Option<T> {
        &self.data
    }
}

impl<'a, T: Into<Vec<u8>>> DerefMut for OutputBuffer<'a, T> {
    fn deref_mut(&mut self) -> &mut Option<T> {
        &mut self.data
    }
}

impl<'a, T: Into<Vec<u8>>> Drop for OutputBuffer<'a, T> {
    fn drop(&mut self) {
        if let Some(buf) = self.data.take() {
            // NB. this should use the same allocator as usercall alloc/free
            let buf: Box<[u8]> = buf.into().into();
            self.buf.len = buf.len();
            self.buf.data = Box::into_raw(buf) as _;
        } else {
            self.buf.len = 0;
        }
    }
}

fn result_from_io_error(err: IoError) -> Result {
    let ret = match err.kind() {
        IoErrorKind::PermissionDenied => Error::PermissionDenied,
        IoErrorKind::NotFound => Error::NotFound,
        IoErrorKind::Interrupted => Error::Interrupted,
        IoErrorKind::ArgumentListTooLong => Error::ArgumentListTooLong,
        IoErrorKind::WouldBlock => Error::WouldBlock,
        IoErrorKind::OutOfMemory => Error::OutOfMemory,
        IoErrorKind::ResourceBusy => Error::ResourceBusy,
        IoErrorKind::AlreadyExists => Error::AlreadyExists,
        IoErrorKind::CrossesDevices => Error::CrossesDevices,
        IoErrorKind::NotADirectory => Error::NotADirectory,
        IoErrorKind::IsADirectory => Error::IsADirectory,
        IoErrorKind::InvalidInput => Error::InvalidInput,
        IoErrorKind::ExecutableFileBusy => Error::ExecutableFileBusy,
        IoErrorKind::FileTooLarge => Error::FileTooLarge,
        IoErrorKind::StorageFull => Error::StorageFull,
        IoErrorKind::NotSeekable => Error::NotSeekable,
        IoErrorKind::ReadOnlyFilesystem => Error::ReadOnlyFilesystem,
        IoErrorKind::TooManyLinks => Error::TooManyLinks,
        IoErrorKind::BrokenPipe => Error::BrokenPipe,
        IoErrorKind::Deadlock => Error::DeadLock,
        IoErrorKind::InvalidFilename => Error::InvalidFilename,
        IoErrorKind::Unsupported => Error::UnSupported,
        IoErrorKind::DirectoryNotEmpty => Error::DirectoryNotEmpty,
        IoErrorKind::AddrInUse => Error::AddrInUse,
        IoErrorKind::AddrNotAvailable => Error::AddrNotAvailable,
        IoErrorKind::NetworkDown => Error::NetworkDown,
        IoErrorKind::NetworkUnreachable => Error::NetworkUnreachable,
        IoErrorKind::ConnectionAborted => Error::ConnectionAborted,
        IoErrorKind::ConnectionReset => Error::ConnectionReset,
        IoErrorKind::NotConnected => Error::NotConnected,
        IoErrorKind::TimedOut => Error::TimedOut,
        IoErrorKind::ConnectionRefused => Error::ConnectionRefused,
        IoErrorKind::HostUnreachable => Error::HostUnreachable,
        IoErrorKind::StaleNetworkFileHandle => Error::StaleNetworkFileHandle,
        IoErrorKind::QuotaExceeded => Error::QuotaExceeded,
        IoErrorKind::InvalidData => Error::InvalidData,
        IoErrorKind::WriteZero => Error::WriteZero,
        IoErrorKind::UnexpectedEof => Error::UnexpectedEof,
        IoErrorKind::Other => Error::Other,
        _ => Error::Other,
    };
    ret as _
}

pub(super) trait ToSgxResult {
    type Return;

    fn to_sgx_result(self) -> Self::Return;
}

pub(super) trait SgxReturn {
    fn on_error() -> Self;
}

impl SgxReturn for u64 {
    fn on_error() -> Self {
        0
    }
}

impl SgxReturn for usize {
    fn on_error() -> Self {
        0
    }
}

impl SgxReturn for *mut u8 {
    fn on_error() -> Self {
        ::std::ptr::null_mut()
    }
}

impl<T: SgxReturn> ToSgxResult for IoResult<T> {
    type Return = (Result, T);

    fn to_sgx_result(self) -> Self::Return {
        match self {
            Err(e) => (result_from_io_error(e), T::on_error()),
            Ok(v) => (RESULT_SUCCESS, v),
        }
    }
}

impl ToSgxResult for IoResult<()> {
    type Return = Result;

    fn to_sgx_result(self) -> Self::Return {
        self.err()
            .map_or(RESULT_SUCCESS, |e| result_from_io_error(e))
    }
}

pub unsafe fn from_raw_parts_nonnull<'a, T>(p: *const T, len: usize) -> IoResult<&'a [T]> {
    if len == 0 {
        Ok(&[])
    } else if p.is_null() {
        Err(IoErrorKind::InvalidInput.into())
    } else {
        Ok(slice::from_raw_parts(p, len))
    }
}

pub unsafe fn from_raw_parts_mut_nonnull<'a, T>(p: *mut T, len: usize) -> IoResult<&'a mut [T]> {
    if len == 0 {
        Ok(&mut [])
    } else if p.is_null() {
        Err(IoErrorKind::InvalidInput.into())
    } else {
        Ok(slice::from_raw_parts_mut(p, len))
    }
}
