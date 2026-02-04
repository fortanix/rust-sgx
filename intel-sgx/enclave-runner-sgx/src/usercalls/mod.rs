/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind as IoErrorKind, Read, Result as IoResult};
use std::pin::Pin;
use std::ptr;
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{self, Duration};
use std::{cmp, fmt, str};

use anyhow::bail;
use fnv::FnvHashMap;
use fortanix_sgx_abi::*;
use futures::future::{poll_fn, Either, Future, FutureExt};
use futures::lock::Mutex;
use insecure_time::{Freq, Rdtscp};
use ipc_queue::position::WritePosition;
use ipc_queue::{DescriptorGuard, Identified, QueueEvent};
use lazy_static::lazy_static;
#[cfg(unix)]
use libc::*;
#[cfg(unix)]
use nix::sys::signal;
use sgxs::loader::Tcs as SgxsTcs;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc as async_mpsc, oneshot, Semaphore};

use self::abi::dispatch;
use self::abi::ReturnValue;
use self::abi::UsercallList;
use self::interface::ToSgxResult;
use self::interface::{Handler, OutputBuffer};
use crate::loader::{EnclavePanic, ErasedTcs};
use crate::tcs::{self, CoResult, ThreadResult};

pub(crate) mod abi;
mod interface;

lazy_static! {
    static ref DEBUGGER_TOGGLE_SYNC: Mutex<()> = Mutex::new(());
}

const NANOS_PER_SEC: u64 = 1_000_000_000;

static TIME_INFO: LazyLock<Option<InsecureTimeInfo>> = LazyLock::new(|| {
    if Rdtscp::is_supported() {
        if let Ok(frequency) = Freq::get() {
            return Some(InsecureTimeInfo {
                version: 0,
                frequency: frequency.as_u64(),
            });
        }
    }
    None
});

// This is not an event in the sense that it could be passed to `send()` or
// `wait()` usercalls in enclave code. However, it's easier for the enclave
// runner implementation to lump it in with events. Also note that this constant
// is not public.
const EV_ABORT: u64 = 0b0000_0000_0001_0000;

const USERCALL_QUEUE_SIZE: usize = 16;
const RETURN_QUEUE_SIZE: usize = 1024;
const CANCEL_QUEUE_SIZE: usize = USERCALL_QUEUE_SIZE * 2;

enum UsercallSendData {
    Sync(ThreadResult<ErasedTcs>, RunningTcs, RefCell<[u8; 1024]>),
    Async(Identified<Usercall>, Option<oneshot::Receiver<()>>),
}

// This is the same as UsercallSendData except that it can't be Sync(CoResult::Return(...), ...)
enum UsercallHandleData {
    Sync(tcs::Usercall<ErasedTcs>, RunningTcs, RefCell<[u8; 1024]>),
    Async(
        Identified<Usercall>,
        Option<oneshot::Receiver<()>>,
        Option<async_mpsc::UnboundedSender<UsercallEvent>>,
    ),
}

type EnclaveResult = StdResult<(u64, u64), EnclaveAbort<Option<EnclavePanic>>>;

struct ReadOnly<R>(Pin<Box<R>>);
struct WriteOnly<W>(Pin<Box<W>>);

macro_rules! forward {
    (fn $n:ident(mut self: Pin<&mut Self> $(, $p:ident : $t:ty)*) -> $ret:ty) => {
        fn $n(mut self: Pin<&mut Self> $(, $p: $t)*) -> $ret {
            self.0.as_mut().$n($($p),*)
        }
    }
}

impl<R: std::marker::Unpin + AsyncRead> AsyncRead for ReadOnly<R> {
    forward!(fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<tokio::io::Result<()>>);
}

impl<T> AsyncRead for WriteOnly<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }
}

impl<T> AsyncWrite for ReadOnly<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }
}

impl<W: std::marker::Unpin + AsyncWrite> AsyncWrite for WriteOnly<W> {
    forward!(fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<tokio::io::Result<usize>>);
    forward!(fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>>);
    forward!(fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>>);
}

struct Stdin;

impl AsyncRead for Stdin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        const BUF_SIZE: usize = 8192;

        struct AsyncStdin {
            rx: async_mpsc::Receiver<VecDeque<u8>>,
            buf: VecDeque<u8>,
        }

        lazy_static::lazy_static! {
            static ref STDIN: Mutex<AsyncStdin> = {
                let (tx, rx) = async_mpsc::channel(8);
                thread::spawn(move || {
                    let mut buf = [0u8; BUF_SIZE];
                    while let Ok(len) = io::stdin().read(&mut buf) {
                        if len == 0 {
                            continue
                        }

                        if tx.try_send(buf[..len].to_vec().into()).is_err() {
                            return
                        };
                    }
                });
                Mutex::new(AsyncStdin { rx, buf: VecDeque::new() })
            };
        }

        match Pin::new(&mut STDIN.lock()).poll(cx) {
            Poll::Ready(mut stdin) => {
                if stdin.buf.is_empty() {
                    let pipeerr =
                        tokio::io::Error::new(tokio::io::ErrorKind::BrokenPipe, "broken pipe");
                    stdin.buf = match Pin::new(&mut stdin.rx).poll_recv(cx) {
                        Poll::Ready(Some(vec)) => vec,
                        Poll::Ready(None) => return Poll::Ready(Err(pipeerr)),
                        _ => return Poll::Pending,
                    };
                }
                let inbuf = match stdin.buf.as_slices() {
                    (&[], inbuf) => inbuf,
                    (inbuf, _) => inbuf,
                };
                let len = cmp::min(buf.remaining(), inbuf.len());
                buf.put_slice(&inbuf[..len]);
                stdin.buf.drain(..len);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + 'static + Send + Sync {
    fn poll_read_alloc(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<Vec<u8>>> {
        let mut v: Vec<u8> = vec![0; 8192];
        let mut buffer = ReadBuf::new(&mut v);
        self.poll_read(cx, &mut buffer)
            .map(|b| b.map(|_| buffer.filled().to_vec()))
    }
}

impl<S: AsyncRead + AsyncWrite + Sync + Send + 'static> AsyncStream for S {}

/// AsyncListener lets an implementation implement a slightly modified form of `std::net::TcpListener::accept`.
pub trait AsyncListener: 'static + Send {
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively.
    /// If `local_addr` and/or `peer_addr` are not `None`, they will point to an empty `String`.
    /// On success, user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local address received.
    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> Poll<tokio::io::Result<Option<Box<dyn AsyncStream>>>>;
}

struct AsyncStreamAdapter {
    stream: Pin<Box<dyn AsyncStream>>,
    read_queue: VecDeque<Waker>,
    write_queue: VecDeque<Waker>,
    flush_queue: VecDeque<Waker>,
}

fn notify_other_tasks(cx: &mut Context, queue: &mut VecDeque<Waker>) {
    for task in queue.drain(..) {
        if !task.will_wake(&cx.waker()) {
            task.wake();
        }
    }
}

impl AsyncStreamAdapter {
    fn poll_read_alloc(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<tokio::io::Result<Vec<u8>>> {
        match self.stream.as_mut().poll_read_alloc(cx) {
            Poll::Pending => {
                self.read_queue.push_back(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(ret)) => {
                notify_other_tasks(cx, &mut self.read_queue);
                Poll::Ready(Ok(ret))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<tokio::io::Result<()>> {
        match self.stream.as_mut().poll_read(cx, buf) {
            Poll::Pending => {
                self.read_queue.push_back(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                notify_other_tasks(cx, &mut self.read_queue);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        match self.stream.as_mut().poll_write(cx, buf) {
            Poll::Pending => {
                self.write_queue.push_back(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(ret)) => {
                notify_other_tasks(cx, &mut self.write_queue);
                Poll::Ready(Ok(ret))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        match self.stream.as_mut().poll_flush(cx) {
            Poll::Pending => {
                self.flush_queue.push_back(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(ret)) => {
                notify_other_tasks(cx, &mut self.flush_queue);
                Poll::Ready(Ok(ret))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

struct AsyncStreamContainer {
    inner: Mutex<Pin<Box<AsyncStreamAdapter>>>,
}

impl AsyncStreamContainer {
    fn new(s: Box<dyn AsyncStream>) -> Self {
        AsyncStreamContainer {
            inner: Mutex::new(Box::pin(AsyncStreamAdapter {
                stream: s.into(),
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
                flush_queue: VecDeque::new(),
            })),
        }
    }

    async fn async_read(&self, buf: &mut ReadBuf<'_>) -> IoResult<()> {
        poll_fn(|cx| {
            let inner_ref = &mut self.inner.lock();
            let mut inner = Pin::new(inner_ref);
            match inner.as_mut().poll(cx) {
                Poll::Ready(mut adapter) => adapter.as_mut().poll_read(cx, buf),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    async fn async_read_alloc(&self) -> IoResult<Vec<u8>> {
        poll_fn(|cx| {
            let inner_ref = &mut self.inner.lock();
            let mut inner = Pin::new(inner_ref);
            match inner.as_mut().poll(cx) {
                Poll::Ready(mut adapter) => adapter.as_mut().poll_read_alloc(cx),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    async fn async_write(&self, buf: &[u8]) -> IoResult<usize> {
        poll_fn(|cx| {
            let inner_ref = &mut self.inner.lock();
            let mut inner = Pin::new(inner_ref);
            match inner.as_mut().poll(cx) {
                Poll::Ready(mut adapter) => adapter.as_mut().poll_write(cx, buf),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }

    async fn async_flush(&self) -> IoResult<()> {
        poll_fn(|cx| {
            let inner_ref = &mut self.inner.lock();
            let mut inner = Pin::new(inner_ref);
            match inner.as_mut().poll(cx) {
                Poll::Ready(mut adapter) => adapter.as_mut().poll_flush(cx),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

struct AsyncListenerAdapter {
    listener: Pin<Box<dyn AsyncListener>>,
    accept_queue: VecDeque<Waker>,
}

impl AsyncListenerAdapter {
    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> Poll<tokio::io::Result<Option<Box<dyn AsyncStream>>>> {
        match self
            .listener
            .as_mut()
            .poll_accept(cx, local_addr, peer_addr)
        {
            Poll::Pending => {
                self.accept_queue.push_back(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(ret)) => {
                notify_other_tasks(cx, &mut self.accept_queue);
                Poll::Ready(Ok(ret))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

struct AsyncListenerContainer {
    inner: Mutex<Pin<Box<AsyncListenerAdapter>>>,
}

impl AsyncListenerContainer {
    fn new(l: Box<dyn AsyncListener>) -> Self {
        AsyncListenerContainer {
            inner: Mutex::new(Pin::new(Box::new(AsyncListenerAdapter {
                listener: l.into(),
                accept_queue: VecDeque::new(),
            }))),
        }
    }

    async fn async_accept(
        &self,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn AsyncStream>>> {
        let mut local_addr_owned: Option<String> = if local_addr.is_some() {
            Some(String::new())
        } else {
            None
        };
        let mut peer_addr_owned: Option<String> = if peer_addr.is_some() {
            Some(String::new())
        } else {
            None
        };
        let res = poll_fn(|cx| {
            let inner_ref = &mut self.inner.lock();
            let mut inner = Pin::new(inner_ref);
            match inner.as_mut().poll(cx) {
                Poll::Ready(mut adapter) => adapter.as_mut().poll_accept(
                    cx,
                    local_addr_owned.as_mut(),
                    peer_addr_owned.as_mut(),
                ),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        if let Some(local_addr) = local_addr {
            *local_addr = local_addr_owned.unwrap();
        }
        if let Some(peer_addr) = peer_addr {
            *peer_addr = peer_addr_owned.unwrap();
        }
        res
    }
}

impl AsyncListener for tokio::net::TcpListener {
    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> Poll<tokio::io::Result<Option<Box<dyn AsyncStream>>>> {
        match tokio::net::TcpListener::poll_accept(&self, cx) {
            Poll::Ready(Ok((stream, _peer))) => {
                if let Some(local_addr) = local_addr {
                    *local_addr = stream
                        .local_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_err| "error".to_owned());
                }
                if let Some(peer_addr) = peer_addr {
                    *peer_addr = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_err| "error".to_owned());
                }
                Poll::Ready(Ok(Some(Box::new(stream))))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

enum AsyncFileDesc {
    Stream(AsyncStreamContainer),
    Listener(AsyncListenerContainer),
}

impl AsyncFileDesc {
    fn stream(s: Box<dyn AsyncStream>) -> AsyncFileDesc {
        AsyncFileDesc::Stream(AsyncStreamContainer::new(s))
    }

    fn listener(l: Box<dyn AsyncListener>) -> AsyncFileDesc {
        AsyncFileDesc::Listener(AsyncListenerContainer::new(l))
    }

    fn as_stream(&self) -> IoResult<&AsyncStreamContainer> {
        if let AsyncFileDesc::Stream(ref s) = self {
            Ok(s)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }

    fn as_listener(&self) -> IoResult<&AsyncListenerContainer> {
        if let AsyncFileDesc::Listener(ref l) = self {
            Ok(l)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }
}

#[derive(Debug)]
pub(crate) enum EnclaveAbort<T> {
    Exit {
        panic: T,
    },
    /// Secondary threads exiting due to an abort
    Secondary,
    IndefiniteWait,
    InvalidUsercall(u64),
    MainReturned,
}

impl<T> EnclaveAbort<T> {
    fn map_panic<U, F: FnOnce(T) -> U>(self, f: F) -> EnclaveAbort<U> {
        match self {
            EnclaveAbort::Exit { panic } => EnclaveAbort::Exit { panic: f(panic) },
            EnclaveAbort::Secondary => EnclaveAbort::Secondary,
            EnclaveAbort::IndefiniteWait => EnclaveAbort::IndefiniteWait,
            EnclaveAbort::InvalidUsercall(n) => EnclaveAbort::InvalidUsercall(n),
            EnclaveAbort::MainReturned => EnclaveAbort::MainReturned,
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct TcsAddress(usize);

impl ErasedTcs {
    fn address(&self) -> TcsAddress {
        TcsAddress(SgxsTcs::address(self) as _)
    }
}

impl fmt::Pointer for TcsAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self.0 as *const u8).fmt(f)
    }
}

struct StoppedTcs {
    tcs: ErasedTcs,
}

struct IOHandlerInput<'tcs> {
    tcs: Option<&'tcs mut RunningTcs>,
    enclave: Arc<EnclaveState>,
    work_sender: &'tcs crossbeam::channel::Sender<Work>,
}

struct PendingEvents {
    // The Semaphores are basically counting how many times each event set has
    // been sent. The count is decreased when an event set is consumed through
    // `take` or `wait_for` methods by calling `SemaphorePermit::forget`.
    counts: [Semaphore; Self::EV_MAX],
    abort: Semaphore,
}

impl PendingEvents {
    // Will error if it doesn't fit in a `u64`
    const EV_MAX_U64: u64 =
        (EV_USERCALLQ_NOT_FULL | EV_RETURNQ_NOT_EMPTY | EV_UNPARK | EV_CANCELQ_NOT_FULL) + 1;
    const EV_MAX: usize = Self::EV_MAX_U64 as _;
    // Will error if it doesn't fit in a `usize`
    const _ERROR_IF_USIZE_TOO_SMALL: u64 = u64::MAX + (Self::EV_MAX_U64 - (Self::EV_MAX as u64));
    const _EV_MAX_U16: u16 = Self::EV_MAX_U64 as u16;
    // Will error if it doesn't fit in a `u16`. We should consider a different approach if we reach this limit.
    const _ERROR_IF_TOO_BIG: u64 = u64::MAX + (Self::EV_MAX_U64 - (Self::_EV_MAX_U16 as u64));

    fn new() -> Self {
        PendingEvents {
            counts: [
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
                Semaphore::new(0),
            ],
            abort: Semaphore::new(0),
        }
    }

    fn take(&self, event_mask: u64) -> Option<u64> {
        assert!(event_mask < Self::EV_MAX_U64);

        if let Ok(_) = self.abort.try_acquire() {
            return Some(EV_ABORT);
        }

        for i in (1..Self::EV_MAX).rev() {
            let ev = i as u64;
            if (ev & event_mask) != 0 {
                if let Ok(permit) = self.counts[i].try_acquire() {
                    permit.forget();
                    return Some(ev);
                }
            }
        }
        None
    }

    async fn wait_for(&self, event_mask: u64) -> u64 {
        assert!(event_mask < Self::EV_MAX_U64);

        if let Ok(_) = self.abort.try_acquire() {
            return EV_ABORT;
        }

        let it = std::iter::once((EV_ABORT, &self.abort))
            .chain(
                self.counts
                    .iter()
                    .enumerate()
                    .map(|(ev, sem)| (ev as u64, sem))
                    .filter(|&(ev, _)| ev & event_mask != 0),
            )
            .map(|(ev, sem)| sem.acquire().map(move |permit| (ev, permit)).boxed());

        let ((ev, permit), _, _) = futures::future::select_all(it).await;

        // Abort should take precedence if it happens concurrently with another
        // event. The abort semaphore may not have been selected.
        if let Ok(_) = self.abort.try_acquire() {
            return EV_ABORT;
        }
        if ev != EV_ABORT {
            if let Ok(permit) = permit {
                permit.forget();
            }
        }
        ev
    }

    fn push(&self, event: u64) {
        debug_assert!(event != 0 && event < Self::EV_MAX_U64);
        let index = event as usize;
        // add_permits() panics if the permit limit is exceeded.
        // NOTE: [the documentation] incorrectly specifies the maximum to be
        // `usize::MAX >> 3`, while the actual maximum is `usize::MAX >> 4`.
        // It's possible to have multiple threads pushing the same event
        // concurrently, hence the smaller bound.
        //
        // [the documentation]: https://docs.rs/tokio/0.2.22/tokio/sync/struct.Semaphore.html#method.add_permits
        const MAX_PERMITS: usize = usize::MAX >> 5;
        if self.counts[index].available_permits() < MAX_PERMITS {
            self.counts[index].add_permits(1);
        }
    }

    fn abort(&self) {
        if self.abort.available_permits() == 0 {
            self.abort.add_permits(usize::MAX >> 5);
        }
    }
}

struct RunningTcs {
    tcs_address: TcsAddress,
    mode: EnclaveEntry,
}

enum EnclaveKind {
    Command(Command),
    Library(Library),
}

struct PanicReason {
    primary_panic_reason: Option<EnclaveAbort<EnclavePanic>>,
    other_reasons: Vec<EnclaveAbort<EnclavePanic>>,
}

struct Command {
    panic_reason: Mutex<PanicReason>,
}

struct Library {}

impl EnclaveKind {
    fn as_command(&self) -> Option<&Command> {
        match self {
            EnclaveKind::Command(c) => Some(c),
            _ => None,
        }
    }

    fn _as_library(&self) -> Option<&Library> {
        match self {
            EnclaveKind::Library(l) => Some(l),
            _ => None,
        }
    }
}

struct FifoGuards {
    usercall_queue: DescriptorGuard<Usercall>,
    return_queue: DescriptorGuard<Return>,
    cancel_queue: DescriptorGuard<Cancel>,
    async_queues_called: bool,
}

pub(crate) struct EnclaveState {
    kind: EnclaveKind,
    event_queues: FnvHashMap<TcsAddress, PendingEvents>,
    fds: Mutex<FnvHashMap<Fd, Arc<AsyncFileDesc>>>,
    last_fd: AtomicUsize,
    exiting: AtomicBool,
    usercall_ext: Box<dyn UsercallExtension>,
    threads_queue: crossbeam::queue::SegQueue<StoppedTcs>,
    forward_panics: bool,
    force_time_usercalls: bool,
    // Once set to Some, the guards should not be dropped for the lifetime of the enclave.
    fifo_guards: Mutex<Option<FifoGuards>>,
    return_queue_tx: Mutex<Option<ipc_queue::AsyncSender<Return, QueueSynchronizer>>>,
}

struct Work {
    tcs: RunningTcs,
    entry: CoEntry,
}

enum CoEntry {
    Initial(ErasedTcs, u64, u64, u64, u64, u64),
    Resume(tcs::Usercall<ErasedTcs>, (u64, u64)),
}

impl Work {
    fn do_work(self, io_send_queue: &mut tokio::sync::mpsc::UnboundedSender<UsercallSendData>) {
        let buf = RefCell::new([0u8; 1024]);
        let usercall_send_data = match self.entry {
            CoEntry::Initial(erased_tcs, p1, p2, p3, p4, p5) => {
                let coresult = tcs::coenter(erased_tcs, p1, p2, p3, p4, p5, Some(&buf));
                UsercallSendData::Sync(coresult, self.tcs, buf)
            }
            CoEntry::Resume(usercall, coresult) => {
                let coresult = usercall.coreturn(coresult, Some(&buf));
                UsercallSendData::Sync(coresult, self.tcs, buf)
            }
        };
        // if there is an error do nothing, as it means that the main thread has exited
        let _ = io_send_queue.send(usercall_send_data);
    }
}

enum UsercallEvent {
    Started(u64, oneshot::Sender<()>),
    Finished(u64),
    Cancelled(u64, WritePosition),
}

trait IgnoreCancel {
    fn ignore_cancel(&self) -> bool;
}

impl IgnoreCancel for Identified<Usercall> {
    fn ignore_cancel(&self) -> bool {
        self.data.0 != UsercallList::read as u64
            && self.data.0 != UsercallList::read_alloc as u64
            && self.data.0 != UsercallList::write as u64
            && self.data.0 != UsercallList::accept_stream as u64
            && self.data.0 != UsercallList::connect_stream as u64
            && self.data.0 != UsercallList::wait as u64
    }
}

impl EnclaveState {
    fn event_queue_add_tcs(
        event_queues: &mut FnvHashMap<TcsAddress, PendingEvents>,
        tcs: ErasedTcs,
    ) -> StoppedTcs {
        if event_queues
            .insert(tcs.address(), PendingEvents::new())
            .is_some()
        {
            panic!("duplicate TCS address: {:p}", tcs.address())
        }
        StoppedTcs { tcs }
    }

    fn new(
        kind: EnclaveKind,
        mut event_queues: FnvHashMap<TcsAddress, PendingEvents>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        threads_vector: Vec<ErasedTcs>,
        forward_panics: bool,
        force_time_usercalls: bool,
    ) -> Arc<Self> {
        let mut fds = FnvHashMap::default();

        fds.insert(
            FD_STDIN,
            Arc::new(AsyncFileDesc::stream(Box::new(ReadOnly(Box::pin(Stdin))))),
        );
        fds.insert(
            FD_STDOUT,
            Arc::new(AsyncFileDesc::stream(Box::new(WriteOnly(Box::pin(
                tokio::io::stdout(),
            ))))),
        );
        fds.insert(
            FD_STDERR,
            Arc::new(AsyncFileDesc::stream(Box::new(WriteOnly(Box::pin(
                tokio::io::stderr(),
            ))))),
        );
        let last_fd = AtomicUsize::new(fds.keys().cloned().max().unwrap() as _);

        let usercall_ext = usercall_ext.unwrap_or_else(|| Box::new(UsercallExtensionDefault));

        let threads_queue = crossbeam::queue::SegQueue::new();

        for thread in threads_vector {
            threads_queue.push(Self::event_queue_add_tcs(&mut event_queues, thread));
        }

        Arc::new(EnclaveState {
            kind,
            event_queues,
            fds: Mutex::new(fds),
            last_fd,
            exiting: AtomicBool::new(false),
            usercall_ext,
            threads_queue,
            forward_panics,
            force_time_usercalls,
            fifo_guards: Mutex::new(None),
            return_queue_tx: Mutex::new(None),
        })
    }

    async fn handle_usercall(
        enclave: Arc<EnclaveState>,
        work_sender: crossbeam::channel::Sender<Work>,
        tx_return_channel: tokio::sync::mpsc::UnboundedSender<(EnclaveResult, ReturnSource)>,
        mut handle_data: UsercallHandleData,
    ) {
        let notifier_rx = match handle_data {
            UsercallHandleData::Async(_, ref mut notifier_rx, _) => notifier_rx.take(),
            _ => None,
        };
        let (parameters, mode, tcs) = match handle_data {
            UsercallHandleData::Sync(ref usercall, ref mut tcs, _) => {
                (usercall.parameters(), tcs.mode.into(), Some(tcs))
            }
            UsercallHandleData::Async(ref usercall, _, _) => {
                (usercall.data.into(), ReturnSource::AsyncUsercall, None)
            }
        };
        let mut input = IOHandlerInput {
            enclave: enclave.clone(),
            tcs,
            work_sender: &work_sender,
        };
        let handler = Handler(&mut input);
        let result = {
            let (p1, p2, p3, p4, p5) = parameters;
            match notifier_rx {
                None => dispatch(handler, p1, p2, p3, p4, p5).await.1,
                Some(notifier_rx) => {
                    let a = dispatch(handler, p1, p2, p3, p4, p5).boxed_local();
                    let b = notifier_rx;
                    match futures::future::select(a, b).await {
                        Either::Left((ret, _)) => ret.1,
                        Either::Right((Ok(()), _)) => {
                            let result: IoResult<usize> = Err(IoErrorKind::Interrupted.into());
                            ReturnValue::into_registers(Ok(result.to_sgx_result()))
                        }
                        Either::Right((Err(_), _)) => {
                            panic!("notifier channel closed unexpectedly")
                        }
                    }
                }
            }
        };
        let ret = match result {
            Ok(ret) => {
                match handle_data {
                    UsercallHandleData::Sync(usercall, tcs, _) => {
                        work_sender
                            .send(Work {
                                tcs,
                                entry: CoEntry::Resume(usercall, ret),
                            })
                            .expect("Work sender couldn't send data to receiver");
                    }
                    UsercallHandleData::Async(usercall, _, usercall_event_tx) => {
                        if let Some(usercall_event_tx) = usercall_event_tx {
                            usercall_event_tx
                                .send(UsercallEvent::Finished(usercall.id))
                                .ok()
                                .expect("failed to send usercall event");
                        }
                        let return_queue_tx = enclave
                            .return_queue_tx
                            .lock()
                            .await
                            .clone()
                            .expect("return_queue_tx not initialized");
                        let ret = Identified {
                            id: usercall.id,
                            data: Return(ret.0, ret.1),
                        };
                        return_queue_tx.send(ret).await.unwrap();
                    }
                }
                return;
            }
            Err(EnclaveAbort::Exit { panic: true }) => {
                let panic = match handle_data {
                    UsercallHandleData::Sync(usercall, _, debug_buf) => {
                        let debug_buf = debug_buf.into_inner();
                        #[cfg(unix)]
                        {
                            eprintln!("Attaching debugger");
                            trap_attached_debugger(usercall.tcs_address() as _, debug_buf.as_ptr())
                                .await;
                        }
                        EnclavePanic::from(debug_buf)
                    }
                    UsercallHandleData::Async(_, _, _) => {
                        // TODO: https://github.com/fortanix/rust-sgx/issues/235#issuecomment-641811437
                        EnclavePanic::DebugStr("async exit with a panic".to_owned())
                    }
                };
                Err(EnclaveAbort::Exit { panic: Some(panic) })
            }
            Err(EnclaveAbort::Exit { panic: false }) => Err(EnclaveAbort::Exit { panic: None }),
            Err(EnclaveAbort::IndefiniteWait) => Err(EnclaveAbort::IndefiniteWait),
            Err(EnclaveAbort::InvalidUsercall(n)) => Err(EnclaveAbort::InvalidUsercall(n)),
            Err(EnclaveAbort::MainReturned) => Err(EnclaveAbort::MainReturned),
            Err(EnclaveAbort::Secondary) => Err(EnclaveAbort::Secondary),
        };
        let _ = tx_return_channel.send((ret, mode));
    }

    fn syscall_loop(
        enclave: Arc<EnclaveState>,
        mut io_queue_receive: tokio::sync::mpsc::UnboundedReceiver<UsercallSendData>,
        io_queue_send: tokio::sync::mpsc::UnboundedSender<UsercallSendData>,
        work_sender: crossbeam::channel::Sender<Work>,
    ) -> EnclaveResult {
        let (tx_return_channel, mut rx_return_channel) = tokio::sync::mpsc::unbounded_channel();
        let enclave_clone = enclave.clone();
        let mut rt = RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio Runtime");
        let local_set = tokio::task::LocalSet::new();

        let return_future = async move {
            while let Some((my_result, mode)) = rx_return_channel.recv().await {
                if enclave_clone.forward_panics {
                    if let Err(EnclaveAbort::Exit { panic: Some(panic) }) = &my_result {
                        panic!("{}", panic);
                    }
                }

                let res = match (my_result, mode) {
                    (Err(EnclaveAbort::Secondary), _)
                    | (Ok(_), ReturnSource::ExecutableNonMain) => continue,

                    (e, ReturnSource::Library)
                    | (e, ReturnSource::ExecutableMain)
                    | (e @ Err(EnclaveAbort::Exit { panic: None }), _) => e,

                    (Ok(_), ReturnSource::AsyncUsercall)
                    | (Err(EnclaveAbort::MainReturned), ReturnSource::AsyncUsercall) => {
                        unreachable!()
                    }

                    (Err(e @ EnclaveAbort::Exit { panic: Some(_) }), _)
                    | (Err(e @ EnclaveAbort::InvalidUsercall(_)), _) => {
                        let e = e.map_panic(|opt| opt.unwrap());
                        let cmd = enclave_clone.kind.as_command().unwrap();
                        let mut cmddata = cmd.panic_reason.lock().await;

                        if cmddata.primary_panic_reason.is_none() {
                            cmddata.primary_panic_reason = Some(e)
                        } else {
                            cmddata.other_reasons.push(e)
                        }
                        Err(EnclaveAbort::Secondary)
                    }

                    (Err(e), _) => {
                        let e = e.map_panic(|opt| opt.unwrap());
                        let cmd = enclave_clone.kind.as_command().unwrap();
                        let mut cmddata = cmd.panic_reason.lock().await;
                        cmddata.other_reasons.push(e);
                        continue;
                    }
                };
                return res;
            }
            unreachable!();
        };
        let enclave_clone = enclave.clone();
        let io_future = async move {
            let (uqs, rqs, cqs, sync_usercall_tx) = QueueSynchronizer::new(enclave_clone.clone());

            let (usercall_queue_tx, usercall_queue_rx) =
                ipc_queue::bounded_async(USERCALL_QUEUE_SIZE, uqs);
            let (return_queue_tx, return_queue_rx) =
                ipc_queue::bounded_async(RETURN_QUEUE_SIZE, rqs);
            let (cancel_queue_tx, cancel_queue_rx) =
                ipc_queue::bounded_async(CANCEL_QUEUE_SIZE, cqs);

            let fifo_guards = FifoGuards {
                usercall_queue: usercall_queue_tx.into_descriptor_guard(),
                return_queue: return_queue_rx.into_descriptor_guard(),
                cancel_queue: cancel_queue_tx.into_descriptor_guard(),
                async_queues_called: false,
            };

            *enclave_clone.fifo_guards.lock().await = Some(fifo_guards);
            *enclave_clone.return_queue_tx.lock().await = Some(return_queue_tx);

            let usercall_queue_monitor = usercall_queue_rx.position_monitor();

            let (usercall_event_tx, mut usercall_event_rx) = async_mpsc::unbounded_channel();
            let usercall_event_tx_clone = usercall_event_tx.clone();
            tokio::task::spawn_local(async move {
                while let Ok(usercall) = usercall_queue_rx.recv().await {
                    let notifier_rx = if usercall.ignore_cancel() {
                        None
                    } else {
                        let (notifier_tx, notifier_rx) = oneshot::channel();
                        usercall_event_tx_clone
                            .send(UsercallEvent::Started(usercall.id, notifier_tx))
                            .ok()
                            .expect("failed to send usercall event");
                        Some(notifier_rx)
                    };
                    let _ = io_queue_send.send(UsercallSendData::Async(usercall, notifier_rx));
                }
            });

            let usercall_event_tx_clone = usercall_event_tx.clone();
            let usercall_queue_monitor_clone = usercall_queue_monitor.clone();
            tokio::task::spawn_local(async move {
                while let Ok(c) = cancel_queue_rx.recv().await {
                    let write_position = usercall_queue_monitor_clone.write_position();
                    let _ = usercall_event_tx_clone
                        .send(UsercallEvent::Cancelled(c.id, write_position));
                }
            });

            tokio::task::spawn_local(async move {
                let mut notifiers = HashMap::new();
                let mut cancels: HashMap<u64, WritePosition> = HashMap::new();
                loop {
                    match usercall_event_rx
                        .recv()
                        .await
                        .expect("usercall_event channel closed unexpectedly")
                    {
                        UsercallEvent::Started(id, notifier) => match cancels.remove(&id) {
                            Some(_) => {
                                let _ = notifier.send(());
                            }
                            _ => {
                                notifiers.insert(id, notifier);
                            }
                        },
                        UsercallEvent::Finished(id) => {
                            notifiers.remove(&id);
                        }
                        UsercallEvent::Cancelled(id, wp) => match notifiers.remove(&id) {
                            Some(notifier) => {
                                let _ = notifier.send(());
                            }
                            None => {
                                cancels.insert(id, wp);
                            }
                        },
                    }
                    // cleanup old cancels
                    let read_position = usercall_queue_monitor.read_position();
                    cancels.retain(|_id, wp| {
                        if let Some(past) = read_position.is_past(wp) {
                            !past
                        } else {
                            false
                        }
                    });
                }
            });

            while let Some(work) = io_queue_receive.recv().await {
                let enclave_clone = enclave_clone.clone();
                let tx_return_channel = tx_return_channel.clone();
                match work {
                    UsercallSendData::Async(usercall, notifier_rx) => {
                        let usercall_event_tx = if usercall.ignore_cancel() {
                            None
                        } else {
                            Some(usercall_event_tx.clone())
                        };
                        let uchd =
                            UsercallHandleData::Async(usercall, notifier_rx, usercall_event_tx);
                        let fut = Self::handle_usercall(
                            enclave_clone,
                            work_sender.clone(),
                            tx_return_channel,
                            uchd,
                        );
                        tokio::task::spawn_local(fut);
                    }
                    UsercallSendData::Sync(CoResult::Yield(usercall), state, buf) => {
                        let _ = sync_usercall_tx.send(());
                        let uchd = UsercallHandleData::Sync(usercall, state, buf);
                        let fut = Self::handle_usercall(
                            enclave_clone,
                            work_sender.clone(),
                            tx_return_channel,
                            uchd,
                        );
                        tokio::task::spawn_local(fut);
                    }
                    UsercallSendData::Sync(CoResult::Return((tcs, v1, v2)), state, _buf) => {
                        let fut = async move {
                            let ret = match state.mode {
                                EnclaveEntry::Library => {
                                    enclave_clone.threads_queue.push(StoppedTcs { tcs });
                                    Ok((v1, v2))
                                }
                                EnclaveEntry::ExecutableMain => Err(EnclaveAbort::MainReturned),
                                EnclaveEntry::ExecutableNonMain => {
                                    assert_eq!(
                                        (v1, v2),
                                        (0, 0),
                                        "Expected enclave thread entrypoint to return zero"
                                    );
                                    // If the enclave is in the exit-state, threads are no
                                    // longer able to be launched
                                    if !enclave_clone.exiting.load(Ordering::SeqCst) {
                                        enclave_clone.threads_queue.push(StoppedTcs { tcs });
                                    }
                                    Ok((0, 0))
                                }
                            };
                            let _ = tx_return_channel.send((ret, state.mode.into()));
                        };
                        tokio::task::spawn_local(fut);
                    }
                };
            }
            unreachable!();
        };

        // Note that:
        // - io_future will never return, its job is to spawn new futures that handle I/O.
        // - return_future returns in certain cases (see above) and in such cases we want to
        //   terminate the syscall loop.
        let select_fut =
            futures::future::select(return_future.boxed_local(), io_future.boxed_local()).map(
                |either| match either {
                    Either::Left((x, _)) => x,
                    _ => unreachable!(),
                },
            );

        local_set
            .block_on(&mut rt, select_fut.unit_error())
            .unwrap()
    }

    fn run(
        enclave: Arc<EnclaveState>,
        num_of_worker_threads: usize,
        start_work: Work,
    ) -> EnclaveResult {
        fn create_worker_threads(
            num_of_worker_threads: usize,
            work_receiver: crossbeam::channel::Receiver<Work>,
            io_queue_send: tokio::sync::mpsc::UnboundedSender<UsercallSendData>,
        ) -> Vec<JoinHandle<()>> {
            let mut thread_handles = vec![];
            for _ in 0..num_of_worker_threads {
                let work_receiver = work_receiver.clone();
                let mut io_queue_send = io_queue_send.clone();

                thread_handles.push(thread::spawn(move || {
                    while let Ok(work) = work_receiver.recv() {
                        work.do_work(&mut io_queue_send);
                    }
                }));
            }
            thread_handles
        }

        let (io_queue_send, io_queue_receive) = tokio::sync::mpsc::unbounded_channel();

        let (work_sender, work_receiver) = crossbeam::channel::unbounded();
        work_sender
            .send(start_work)
            .expect("Work sender couldn't send data to receiver");

        let join_handlers =
            create_worker_threads(num_of_worker_threads, work_receiver, io_queue_send.clone());
        // main syscall polling loop
        let main_result = EnclaveState::syscall_loop(
            enclave.clone(),
            io_queue_receive,
            io_queue_send,
            work_sender,
        );

        for handler in join_handlers {
            let _ = handler.join();
        }

        main_result
    }

    pub(crate) fn main_entry(
        main: ErasedTcs,
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        forward_panics: bool,
        force_time_usercalls: bool,
        cmd_args: Vec<Vec<u8>>,
        num_of_worker_threads: usize,
    ) -> StdResult<(), anyhow::Error> {
        assert!(num_of_worker_threads > 0, "worker_threads cannot be zero");
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
        let main = Self::event_queue_add_tcs(&mut event_queues, main);

        let mut args = Vec::with_capacity(cmd_args.len());
        for a in cmd_args {
            args.push(ByteBuffer {
                len: a.len(),
                data: Box::into_raw(a.into_boxed_slice()) as *const u8,
            });
        }
        let argc = args.len();
        let argv = Box::into_raw(args.into_boxed_slice()) as *const u8;

        let main_work = Work {
            tcs: RunningTcs {
                tcs_address: main.tcs.address(),
                mode: EnclaveEntry::ExecutableMain,
            },
            entry: CoEntry::Initial(main.tcs, argv as _, argc as _, 0, 0, 0),
        };

        let kind = EnclaveKind::Command(Command {
            panic_reason: Mutex::new(PanicReason {
                primary_panic_reason: None,
                other_reasons: vec![],
            }),
        });
        let enclave = EnclaveState::new(
            kind,
            event_queues,
            usercall_ext,
            threads,
            forward_panics,
            force_time_usercalls,
        );

        let main_result = EnclaveState::run(enclave.clone(), num_of_worker_threads, main_work);

        let main_panicking = match main_result {
            Err(EnclaveAbort::MainReturned)
            | Err(EnclaveAbort::InvalidUsercall(_))
            | Err(EnclaveAbort::Exit { .. }) => true,
            Err(EnclaveAbort::IndefiniteWait) | Err(EnclaveAbort::Secondary) | Ok(_) => false,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio Runtime");

        rt.block_on(async move {
            enclave.abort_all_threads();
            //clear the threads_queue
            while enclave.threads_queue.pop().is_some() {}

            let cmd = enclave.kind.as_command().unwrap();
            let mut cmddata = cmd.panic_reason.lock().await;
            let main_result = match (main_panicking, cmddata.primary_panic_reason.take()) {
                (false, Some(reason)) => Err(reason.map_panic(Some)),
                // TODO: interpret other_reasons
                _ => main_result,
            };
            match main_result {
                Err(EnclaveAbort::Exit { panic: None }) => Ok(()),
                Err(EnclaveAbort::Exit { panic: Some(panic) }) => Err(panic.into()),
                Err(EnclaveAbort::IndefiniteWait) => {
                    bail!("All enclave threads are waiting indefinitely without possibility of wakeup")
                }
                Err(EnclaveAbort::InvalidUsercall(n)) => {
                    bail!("The enclave performed an invalid usercall 0x{:x}", n)
                }
                Err(EnclaveAbort::MainReturned) => bail!(
                    "The enclave returned from the main entrypoint in violation of the specification."
                ),
                // Should always be able to return the real exit reason
                Err(EnclaveAbort::Secondary) => unreachable!(),
                Ok(_) => Ok(()),
            }
        }.boxed_local())
    }

    pub(crate) fn library(
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        forward_panics: bool,
        force_time_usercalls: bool,
    ) -> Arc<Self> {
        let event_queues = FnvHashMap::with_capacity_and_hasher(threads.len(), Default::default());

        let kind = EnclaveKind::Library(Library {});

        let enclave = EnclaveState::new(
            kind,
            event_queues,
            usercall_ext,
            threads,
            forward_panics,
            force_time_usercalls,
        );
        return enclave;
    }

    pub(crate) fn library_entry(
        enclave: &Arc<Self>,
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    ) -> StdResult<(u64, u64), anyhow::Error> {
        let thread = enclave.threads_queue.pop().expect("threads queue empty");
        let work = Work {
            tcs: RunningTcs {
                tcs_address: thread.tcs.address(),
                mode: EnclaveEntry::Library,
            },
            entry: CoEntry::Initial(thread.tcs, p1, p2, p3, p4, p5),
        };
        // As currently we are not supporting spawning threads let the number of threads be 2
        // one for usercall handling the other for actually running
        let num_of_worker_threads = 1;

        let library_result = EnclaveState::run(enclave.clone(), num_of_worker_threads, work);

        match library_result {
            Err(EnclaveAbort::Exit { panic: None }) => bail!("This thread aborted execution"),
            Err(EnclaveAbort::Exit { panic: Some(panic) }) => Err(panic.into()),
            Err(EnclaveAbort::IndefiniteWait) => {
                bail!("This thread is waiting indefinitely without possibility of wakeup")
            }
            Err(EnclaveAbort::InvalidUsercall(n)) => {
                bail!("The enclave performed an invalid usercall 0x{:x}", n)
            }
            Err(EnclaveAbort::Secondary) => {
                bail!("This thread exited because another thread aborted")
            }
            Err(EnclaveAbort::MainReturned) => unreachable!(),
            Ok(result) => Ok(result),
        }
    }

    fn abort_all_threads(&self) {
        self.exiting.store(true, Ordering::SeqCst);
        // wake other threads
        for pending_events in self.event_queues.values() {
            pending_events.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnclaveEntry {
    ExecutableMain,
    ExecutableNonMain,
    Library,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReturnSource {
    ExecutableMain,
    ExecutableNonMain,
    Library,
    AsyncUsercall,
}

impl From<EnclaveEntry> for ReturnSource {
    fn from(e: EnclaveEntry) -> Self {
        match e {
            EnclaveEntry::ExecutableMain => ReturnSource::ExecutableMain,
            EnclaveEntry::ExecutableNonMain => ReturnSource::ExecutableNonMain,
            EnclaveEntry::Library => ReturnSource::Library,
        }
    }
}

#[repr(C)]
#[allow(unused)]
enum Greg {
    R8 = 0,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RDI,
    RSI,
    RBP,
    RBX,
    RDX,
    RAX,
    RCX,
    RSP,
    RIP,
    EFL,
    CSGSFS, /* Actually short cs, gs, fs, __pad0. */
    ERR,
    TRAPNO,
    OLDMASK,
    CR2,
}

#[cfg(unix)]
/* Here we are passing control to debugger `fixup` style by raising Sigtrap.
 * If there is no debugger attached, this function, would skip the `int3` instructon
 * and resume execution.
 */
extern "C" fn handle_trap(_signo: c_int, _info: *mut siginfo_t, context: *mut c_void) {
    unsafe {
        let context = &mut *(context as *mut ucontext_t);
        let rip = &mut context.uc_mcontext.gregs[Greg::RIP as usize];
        let inst: *const u8 = *rip as _;
        if *inst == 0xcc {
            *rip += 1;
        }
    }
    return;
}

#[cfg(unix)]
/* Raising Sigtrap to allow debugger to take control.
 * Here, we also store tcs in rbx, so that the debugger could read it, to
 * set sgx state and correctly map the enclave symbols.
 */
async fn trap_attached_debugger(tcs: usize, debug_buf: *const u8) {
    let _g = DEBUGGER_TOGGLE_SYNC.lock().await;
    let hdl = self::signal::SigHandler::SigAction(handle_trap);
    let sig_action = signal::SigAction::new(hdl, signal::SaFlags::empty(), signal::SigSet::empty());
    // Synchronized
    unsafe {
        let old = signal::sigaction(signal::SIGTRAP, &sig_action).unwrap();
        std::arch::asm!("
            xchg %rbx, {0}
            int3
            xchg {0}, %rbx
            ",
            in(reg) tcs, // rbx is used internally by LLVM and cannot be used as an operand for inline asm (#84658)
            in("r10") debug_buf,
            options(nomem, nostack, att_syntax));
        signal::sigaction(signal::SIGTRAP, &old).unwrap();
    }
}

/// Provides a mechanism for the enclave code to interface with an external service via a modified runner.
///
/// An implementation of `UsercallExtension` can be registered while [building](../struct.EnclaveBuilder.html#method.usercall_extension) the enclave.
pub trait UsercallExtension: 'static + Send + Sync + std::fmt::Debug {
    /// Override the connection target for connect calls by the enclave. The runner should determine the service that the enclave is trying to connect to by looking at addr.
    /// If `connect_stream` returns None, the default implementation of [`connect_stream`](../../fortanix_sgx_abi/struct.Usercalls.html#method.connect_stream) is used.
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively.
    /// If `local_addr` and/or `peer_addr` are not `None`, they will point to an empty `String`.
    /// On success, user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local or
    /// peer address received.
    #[allow(unused)]
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
        peer_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>>
    {
        async { Ok(None) }.boxed_local()
    }

    /// Override the target for bind calls by the enclave. The runner should determine the service that the enclave is trying to bind to by looking at addr.
    /// If `bind_stream` returns None, the default implementation of [`bind_stream`](../../fortanix_sgx_abi/struct.Usercalls.html#method.bind_stream) is used.
    /// The enclave may optionally request the local address be returned in `local_addr`.
    /// If `local_addr` is not `None`, it will point to an empty `String`.
    /// On success, user-space can fill in the string as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local address received.
    #[allow(unused)]
    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncListener>>>> + 'future>>
    {
        async { Ok(None) }.boxed_local()
    }
}

impl<T: UsercallExtension> From<T> for Box<dyn UsercallExtension> {
    fn from(value: T) -> Box<dyn UsercallExtension> {
        Box::new(value)
    }
}

#[derive(Debug)]
struct UsercallExtensionDefault;
impl UsercallExtension for UsercallExtensionDefault {}

impl<'tcs> IOHandlerInput<'tcs> {
    async fn lookup_fd(&self, fd: Fd) -> IoResult<Arc<AsyncFileDesc>> {
        match self.enclave.fds.lock().await.get(&fd) {
            Some(stream) => Ok(stream.clone()),
            None => Err(IoErrorKind::BrokenPipe.into()), // FIXME: Rust normally maps Unix EBADF to `Other`
        }
    }

    async fn alloc_fd(&self, stream: AsyncFileDesc) -> Fd {
        let fd = (self
            .enclave
            .last_fd
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("FD overflow")) as Fd;
        let prev = self.enclave.fds.lock().await.insert(fd, Arc::new(stream));
        debug_assert!(prev.is_none());
        fd
    }

    #[inline(always)]
    fn is_exiting(&self) -> bool {
        self.enclave.exiting.load(Ordering::SeqCst)
    }

    #[inline(always)]
    async fn read(&self, fd: Fd, buf: &mut ReadBuf<'_>) -> IoResult<()> {
        let file_desc = self.lookup_fd(fd).await?;
        file_desc.as_stream()?.async_read(buf).await
    }

    #[inline(always)]
    async fn read_alloc(&self, fd: Fd, buf: &mut OutputBuffer<'tcs>) -> IoResult<()> {
        let file_desc = self.lookup_fd(fd).await?;
        let v = file_desc.as_stream()?.async_read_alloc().await?;
        buf.set(v);
        Ok(())
    }

    #[inline(always)]
    async fn write(&self, fd: Fd, buf: &[u8]) -> IoResult<usize> {
        let file_desc = self.lookup_fd(fd).await?;
        return file_desc.as_stream()?.async_write(buf).await;
    }

    #[inline(always)]
    async fn flush(&self, fd: Fd) -> IoResult<()> {
        let file_desc = self.lookup_fd(fd).await?;
        file_desc.as_stream()?.async_flush().await
    }

    #[inline(always)]
    async fn close(&self, fd: Fd) {
        self.enclave.fds.lock().await.remove(&fd);
    }

    #[inline(always)]
    async fn bind_stream(
        &self,
        addr: &[u8],
        local_addr: Option<&mut OutputBuffer<'tcs>>,
    ) -> IoResult<Fd> {
        let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        if let Some(stream_ext) = self
            .enclave
            .usercall_ext
            .bind_stream(addr, local_addr_str.as_mut())
            .await?
        {
            if let Some(local_addr) = local_addr {
                local_addr.set(local_addr_str.unwrap().into_bytes());
            }
            return Ok(self.alloc_fd(AsyncFileDesc::listener(stream_ext)).await);
        }

        let socket = tokio::net::TcpListener::bind(addr).await?;
        if let Some(local_addr) = local_addr {
            local_addr.set(socket.local_addr()?.to_string().into_bytes());
        }
        Ok(self
            .alloc_fd(AsyncFileDesc::listener(Box::new(socket)))
            .await)
    }

    #[inline(always)]
    async fn accept_stream(
        &self,
        fd: Fd,
        local_addr: Option<&mut OutputBuffer<'tcs>>,
        peer_addr: Option<&mut OutputBuffer<'tcs>>,
    ) -> IoResult<Fd> {
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        let mut peer_addr_str = peer_addr.as_ref().map(|_| String::new());

        let file_desc = self.lookup_fd(fd).await?;
        let stream = file_desc
            .as_listener()?
            .async_accept(local_addr_str.as_mut(), peer_addr_str.as_mut())
            .await?
            .unwrap();

        if let Some(local_addr) = local_addr {
            local_addr.set(&local_addr_str.unwrap().into_bytes()[..])
        }
        if let Some(peer_addr) = peer_addr {
            peer_addr.set(&peer_addr_str.unwrap().into_bytes()[..])
        }
        Ok(self.alloc_fd(AsyncFileDesc::stream(stream)).await)
    }

    #[inline(always)]
    async fn connect_stream(
        &self,
        addr: &[u8],
        local_addr: Option<&mut OutputBuffer<'tcs>>,
        peer_addr: Option<&mut OutputBuffer<'tcs>>,
    ) -> IoResult<Fd> {
        let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        let mut peer_addr_str = peer_addr.as_ref().map(|_| String::new());
        if let Some(stream_ext) = self
            .enclave
            .usercall_ext
            .connect_stream(addr, local_addr_str.as_mut(), peer_addr_str.as_mut())
            .await?
        {
            if let Some(local_addr) = local_addr {
                local_addr.set(local_addr_str.unwrap().into_bytes());
            }
            if let Some(peer_addr) = peer_addr {
                peer_addr.set(peer_addr_str.unwrap().into_bytes());
            }
            return Ok(self.alloc_fd(AsyncFileDesc::stream(stream_ext)).await);
        }

        let stream = tokio::net::TcpStream::connect(addr).await?;

        if let Some(local_addr) = local_addr {
            match stream.local_addr() {
                Ok(local) => local_addr.set(local.to_string().into_bytes()),
                Err(_) => local_addr.set(&b"error"[..]),
            }
        }
        if let Some(peer_addr) = peer_addr {
            match stream.peer_addr() {
                Ok(peer) => peer_addr.set(peer.to_string().into_bytes()),
                Err(_) => peer_addr.set(&b"error"[..]),
            }
        }
        Ok(self.alloc_fd(AsyncFileDesc::stream(Box::new(stream))).await)
    }

    #[inline(always)]
    fn launch_thread(&self) -> IoResult<()> {
        // check if enclave is of type command
        self.enclave
            .kind
            .as_command()
            .ok_or(IoErrorKind::InvalidInput)?;
        let new_tcs = match self.enclave.threads_queue.pop() {
            Some(tcs) => tcs,
            None => {
                return Err(IoErrorKind::WouldBlock.into());
            }
        };

        let ret = self.work_sender.send(Work {
            tcs: RunningTcs {
                tcs_address: new_tcs.tcs.address(),
                mode: EnclaveEntry::ExecutableNonMain,
            },
            entry: CoEntry::Initial(new_tcs.tcs, 0, 0, 0, 0, 0),
        });
        match ret {
            Ok(()) => Ok(()),
            Err(e) => {
                let entry = e.0.entry;
                match entry {
                    CoEntry::Initial(tcs, _, _, _, _, _) => {
                        self.enclave.threads_queue.push(StoppedTcs { tcs });
                    }
                    _ => unreachable!(),
                };
                Err(std::io::Error::new(
                    IoErrorKind::NotConnected,
                    "Work Sender: send error",
                ))
            }
        }
    }

    #[inline(always)]
    fn exit(&mut self, panic: bool) -> EnclaveAbort<bool> {
        self.enclave.abort_all_threads();
        EnclaveAbort::Exit { panic }
    }

    fn check_event_set(set: u64) -> IoResult<()> {
        const EV_ALL: u64 =
            EV_USERCALLQ_NOT_FULL | EV_RETURNQ_NOT_EMPTY | EV_UNPARK | EV_CANCELQ_NOT_FULL;
        if (set & !EV_ALL) != 0 {
            return Err(IoErrorKind::InvalidInput.into());
        }

        assert!((EV_ALL | EV_ABORT) <= u8::max_value().into());
        assert!((EV_ALL & EV_ABORT) == 0);
        Ok(())
    }

    #[inline(always)]
    async fn wait(&mut self, event_mask: u64, timeout: u64) -> IoResult<u64> {
        Self::check_event_set(event_mask)?;

        let timeout = match timeout {
            WAIT_NO | WAIT_INDEFINITE => timeout,
            _ => {
                // tokio::time::timeout does not handle large timeout values
                // well which may or may not be a bug in tokio, but it seems to
                // work ok with timeout values smaller than 2 ^ 55 nanoseconds.
                // NOTE: 2 ^ 55 nanoseconds is roughly 417 days.
                // TODO: revisit when https://github.com/tokio-rs/tokio/issues/2667 is resolved.
                cmp::min(1 << 55, timeout)
            }
        };

        // TODO: https://github.com/fortanix/rust-sgx/issues/290
        let tcs = self
            .tcs
            .as_mut()
            .ok_or(io::Error::from(io::ErrorKind::Other))?;

        let pending_events = self
            .enclave
            .event_queues
            .get(&tcs.tcs_address)
            .expect("invalid tcs address");

        let ret = match timeout {
            WAIT_NO => pending_events.take(event_mask),
            WAIT_INDEFINITE => Some(pending_events.wait_for(event_mask).await),
            n => tokio::time::timeout(Duration::from_nanos(n), pending_events.wait_for(event_mask))
                .await
                .ok(),
        };

        if let Some(ev) = ret {
            if (ev & EV_ABORT) != 0 {
                // dispatch will make sure this is not returned to enclave
                return Err(IoErrorKind::Other.into());
            }
            return Ok(ev.into());
        }
        Err(if timeout == WAIT_NO {
            IoErrorKind::WouldBlock
        } else {
            IoErrorKind::TimedOut
        }
        .into())
    }

    #[inline(always)]
    fn send(&self, event_set: u64, target: Option<Tcs>) -> IoResult<()> {
        Self::check_event_set(event_set)?;

        if event_set == 0 {
            return Err(IoErrorKind::InvalidInput.into());
        }

        if let Some(tcs) = target {
            let tcs = TcsAddress(tcs.as_ptr() as _);
            let pending_events = self
                .enclave
                .event_queues
                .get(&tcs)
                .ok_or(IoErrorKind::InvalidInput)?;
            pending_events.push(event_set);
        } else {
            for pending_events in self.enclave.event_queues.values() {
                pending_events.push(event_set);
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn insecure_time(&mut self) -> (u64, *const InsecureTimeInfo) {
        let time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        let t = (time.subsec_nanos() as u64) + time.as_secs() * NANOS_PER_SEC;
        let insecure_time_ref: Option<&'static InsecureTimeInfo> = (&*TIME_INFO).as_ref();
        let info =
            if let (Some(info), false) = (insecure_time_ref, self.enclave.force_time_usercalls) {
                info
            } else {
                ptr::null()
            };
        (t, info)
    }

    #[inline(always)]
    fn alloc(&self, size: usize, alignment: usize) -> IoResult<*mut u8> {
        unsafe {
            let layout =
                Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
            if layout.size() == 0 {
                return Err(IoErrorKind::InvalidInput.into());
            }
            let ptr = System.alloc(layout);
            if ptr.is_null() {
                Err(IoErrorKind::Other.into())
            } else {
                Ok(ptr)
            }
        }
    }

    #[inline(always)]
    fn free(&self, ptr: *mut u8, size: usize, alignment: usize) -> IoResult<()> {
        unsafe {
            let layout =
                Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
            if size == 0 {
                return Ok(());
            }
            Ok(System.dealloc(ptr, layout))
        }
    }

    #[inline(always)]
    async fn async_queues(
        &mut self,
        usercall_queue: &mut FifoDescriptor<Usercall>,
        return_queue: &mut FifoDescriptor<Return>,
        cancel_queue: Option<&mut FifoDescriptor<Cancel>>,
    ) -> StdResult<(), EnclaveAbort<bool>> {
        let mut fifo_guards = self.enclave.fifo_guards.lock().await;
        match &mut *fifo_guards {
            Some(ref mut fifo_guards) if !fifo_guards.async_queues_called => {
                *usercall_queue = fifo_guards.usercall_queue.fifo_descriptor();
                *return_queue = fifo_guards.return_queue.fifo_descriptor();
                if let Some(cancel_queue) = cancel_queue {
                    *cancel_queue = fifo_guards.cancel_queue.fifo_descriptor();
                }
                fifo_guards.async_queues_called = true;
                Ok(())
            }
            Some(_) => {
                drop(fifo_guards);
                Err(self.exit(true))
            }
            // Enclave would not be able to call `async_queues()` before the
            // fifo_guards is set to Some in `fn syscall_loop`.
            None => unreachable!(),
        }
    }
}

#[derive(Clone, Copy)]
enum Queue {
    Usercall,
    Return,
    Cancel,
}

struct QueueSynchronizer {
    queue: Queue,
    enclave: Arc<EnclaveState>,
    // the Mutex is uncontested and is used for providing interior mutability.
    subscription: Mutex<broadcast::Receiver<()>>,
    // this is only used to create a new Receiver in the Clone implementation
    subscription_maker: broadcast::Sender<()>,
}

impl QueueSynchronizer {
    fn new(enclave: Arc<EnclaveState>) -> (Self, Self, Self, broadcast::Sender<()>) {
        // This broadcast channel is used to notify enclave-runner of any
        // synchronous usercalls made by the enclave for the purpose of
        // synchronizing access to usercall and return queues.
        // The size of this channel should not matter since recv() can
        // return RecvError::Lagged.
        let (tx, rx1) = broadcast::channel(1);
        let rx2 = tx.subscribe();
        let rx3 = tx.subscribe();
        let usercall_queue_synchronizer = QueueSynchronizer {
            queue: Queue::Usercall,
            enclave: enclave.clone(),
            subscription: Mutex::new(rx1),
            subscription_maker: tx.clone(),
        };
        let return_queue_synchronizer = QueueSynchronizer {
            queue: Queue::Return,
            enclave: enclave.clone(),
            subscription: Mutex::new(rx2),
            subscription_maker: tx.clone(),
        };
        let cancel_queue_synchronizer = QueueSynchronizer {
            queue: Queue::Cancel,
            enclave,
            subscription: Mutex::new(rx3),
            subscription_maker: tx.clone(),
        };
        (
            usercall_queue_synchronizer,
            return_queue_synchronizer,
            cancel_queue_synchronizer,
            tx,
        )
    }
}

impl Clone for QueueSynchronizer {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue,
            enclave: self.enclave.clone(),
            subscription: Mutex::new(self.subscription_maker.subscribe()),
            subscription_maker: self.subscription_maker.clone(),
        }
    }
}

impl ipc_queue::AsyncSynchronizer for QueueSynchronizer {
    fn wait(
        &self,
        event: QueueEvent,
    ) -> Pin<Box<dyn Future<Output = StdResult<(), ipc_queue::SynchronizationError>> + '_>> {
        match (self.queue, event) {
            (Queue::Usercall, QueueEvent::NotFull) => {
                panic!("enclave runner should not send on the usercall queue")
            }
            (Queue::Cancel, QueueEvent::NotFull) => {
                panic!("enclave runner should not send on the cancel queue")
            }
            (Queue::Return, QueueEvent::NotEmpty) => {
                panic!("enclave runner should not receive on the return queue")
            }
            _ => {}
        }
        // When userspace needs to wait on a queue, it will park the current thread (or do whatever
        // else is appropriate for the synchronization model currently in use by userspace).
        // Any synchronous usercall will wake the blocked thread (or otherwise signal that either queue is ready).
        async move {
            let mut subscription = self.subscription.lock().await;
            match subscription.recv().await {
                Ok(()) | Err(RecvError::Lagged(_)) => Ok(()),
                Err(RecvError::Closed) => Err(ipc_queue::SynchronizationError::ChannelClosed),
            }
        }
        .boxed_local()
    }

    fn notify(&self, event: QueueEvent) {
        let ev = match (self.queue, event) {
            (Queue::Usercall, QueueEvent::NotEmpty) => {
                panic!("enclave runner should not send on the usercall queue")
            }
            (Queue::Cancel, QueueEvent::NotEmpty) => {
                panic!("enclave runner should not send on the cancel queue")
            }
            (Queue::Return, QueueEvent::NotFull) => {
                panic!("enclave runner should not receive on the return queue")
            }
            (Queue::Usercall, QueueEvent::NotFull) => EV_USERCALLQ_NOT_FULL,
            (Queue::Return, QueueEvent::NotEmpty) => EV_RETURNQ_NOT_EMPTY,
            (Queue::Cancel, QueueEvent::NotFull) => EV_CANCELQ_NOT_FULL,
        };
        // When the enclave needs to wait on a queue, it executes the wait() usercall synchronously,
        // specifying EV_USERCALLQ_NOT_FULL, EV_RETURNQ_NOT_EMPTY or EV_CANCELQ_NOT_FULL in the event_mask.
        // Userspace will wake any or all threads waiting on the appropriate event when it is triggered.
        for pending_events in self.enclave.event_queues.values() {
            pending_events.push(ev as _);
        }
    }
}
