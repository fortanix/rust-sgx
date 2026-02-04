/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cell::RefCell;
use std::future::Future;
use std::mem;
use std::io::Result as IoResult;
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncRead, AsyncWrite};

mod os;
pub use self::os::OsStreamRouter;

pub trait AsyncStream: AsyncRead + AsyncWrite + 'static + Send + Sync {
    fn poll_read_alloc(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<Vec<u8>>> {
        fn empty_buf() -> Vec<u8> {
            Vec::with_capacity(8192)
        }

        thread_local! {
            static BUF: RefCell<Vec<u8>> = RefCell::new(empty_buf());
        }

        BUF.with_borrow_mut(|buf| {
            pin!(self.read_buf(buf)).poll(cx)
                .map_ok(|len| match len {
                    // read_buf() left buffer empty. Re-use allocation for next call
                    0 => Vec::new(),
                    // read_buf() put some data in the buffer. Return it and allocate a new one
                    _ => mem::replace(buf, empty_buf()),
                })
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Sync + Send + 'static> AsyncStream for S {}

pub trait AsyncListener: 'static + Send {
    /// Serve an accept call by the enclave, for the bound listener `self`.
    ///
    /// The enclave may optionally request the local or peer addresses be 
    /// returned in `local_addr` or `peer_addr`, respectively. If `local_addr` 
    /// and/or `peer_addr` are not [`None`], they will point to an empty 
    /// [`String`]. On success, user-space can fill in the strings as 
    /// appropriate.
    ///
    /// The enclave must not make any security decisions based on the local 
    /// address received.
    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> Poll<tokio::io::Result<Box<dyn AsyncStream>>>;
}

pub trait StreamRouter {
    /// Obtain a list of basic streams that are available to every enclave.
    /// Enclaves access these streams by numeric index in a platform-dependent
    /// way.
    ///
    /// Implementers must ensure that the streams returned by any call to this
    /// function represent the same streams as those returned by any other call.
    /// Synchronization must be taken care of by the implementation.
    ///
    /// Most enclaves expect that the first elements are those returned by an 
    /// instance of [`OsStreamRouter`].
    fn basic_streams(&self) -> Vec<Box<dyn AsyncStream>>;

    /// Serve a connect call by the enclave. The runner should determine the 
    /// service that the enclave is trying to connect to by looking at `addr`.
    ///
    /// Most enclaves expect that unrecognized `addr`s are forwarded to an 
    /// instance of [`OsStreamRouter`].
    ///
    /// The enclave may optionally request the local or peer addresses be 
    /// returned in `local_addr` or `peer_addr`, respectively. If `local_addr` 
    /// and/or `peer_addr` are not [`None`], they will point to an empty 
    /// [`String`]. On success, user-space can fill in the strings as 
    /// appropriate.
    ///
    /// The enclave must not make any security decisions based on the local or 
    /// peer address received.
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
        peer_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Box<dyn AsyncStream>>> +'future>>;

    /// Serve a bind call by the enclave. The runner should determine the 
    /// service that the enclave is trying to bind to by looking at `addr`.
    ///
    /// Most enclaves expect that unrecognized `addr`s are forwarded to an 
    /// instance of [`OsStreamRouter`].
    ///
    /// The enclave may optionally request the local address be returned in 
    /// `local_addr`. If `local_addr` is not [`None`], it will point to an 
    /// empty [`String`]. On success, user-space can fill in the string as 
    /// appropriate.
    ///
    /// The enclave must not make any security decisions based on the local 
    /// address received.
    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Box<dyn AsyncListener>>> + 'future>>;
}
