//! This crate provides an interface for performing asynchronous usercalls in
//! SGX enclaves. The motivation behind asynchronous usercalls and ABI
//! documentation can be found
//! [here](https://edp.fortanix.com/docs/api/fortanix_sgx_abi/async/index.html).
//! The API provided here is fairly low level and is not meant for general use.
//! These APIs can be used to implement [mio] abstractions which in turn
//! allows us to use [tokio] in SGX enclaves!
//!
//! The main interface is provided through `AsyncUsercallProvider` which works
//! in tandem with `CallbackHandler`:
//! ```
//! use async_usercalls::AsyncUsercallProvider;
//! use std::{io::Result, net::TcpStream, sync::mpsc, time::Duration};
//!
//! let (provider, callback_handler) = AsyncUsercallProvider::new();
//! let (tx, rx) = mpsc::sync_channel(1);
//! // The closure is called when userspace sends back the result of the
//! // usercall.
//! let cancel_handle = provider.connect_stream("www.example.com:80", move |res| {
//!     tx.send(res).unwrap();
//! });
//! // We can cancel the connect usercall using `cancel_handle.cancel()`, but
//! // note that we may still get a successful result.
//! // We need to poll `callback_handler` to make progress.
//! loop {
//!     let n = callback_handler.poll(Some(Duration::from_millis(100)));
//!     if n > 0 {
//!         break; // at least 1 callback function was executed!
//!     }
//! }
//! let connect_result: Result<TcpStream> = rx.recv().unwrap();
//! ```
//!
//! [mio]: https://docs.rs/mio/latest/mio/
//! [tokio]: https://docs.rs/tokio/latest/tokio/

#![feature(sgx_platform)]
#![feature(never_type)]
#![cfg_attr(test, feature(unboxed_closures))]
#![cfg_attr(test, feature(fn_traits))]

use crossbeam_channel as mpmc;
use ipc_queue::Identified;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

mod batch_drop;
mod callback;
mod duplicated;
mod hacks;
mod io_bufs;
mod provider_api;
mod provider_core;
mod queues;
mod raw;
#[cfg(test)]
mod test_support;

pub use self::batch_drop::batch_drop;
pub use self::callback::CbFn;
pub use self::io_bufs::{ReadBuffer, UserBuf, WriteBuffer};
pub use self::raw::RawApi;

use self::callback::*;
use self::hacks::{Cancel, Return, Usercall};
use self::provider_core::ProviderCore;
use self::queues::*;

pub struct CancelHandle(Identified<Cancel>);

impl CancelHandle {
    pub fn cancel(self) {
        PROVIDERS
            .cancel_sender()
            .send(self.0)
            .expect("failed to send cancellation");
    }

    pub(crate) fn new(c: Identified<Cancel>) -> Self {
        CancelHandle(c)
    }
}

/// This type provides a mechanism for submitting usercalls asynchronously.
/// Usercalls are sent to the enclave runner through a queue. The results are
/// retrieved when `CallbackHandler::poll` is called. Users are notified of the
/// results through callback functions.
///
/// Users of this type should take care not to block execution in callbacks.
/// Certain usercalls can be cancelled through a handle, but note that it is
/// still possible to receive successful results for cancelled usercalls.
pub struct AsyncUsercallProvider {
    core: ProviderCore,
    callback_tx: mpmc::Sender<(u64, Callback)>,
}

impl AsyncUsercallProvider {
    pub fn new() -> (Self, CallbackHandler) {
        let (return_tx, return_rx) = mpmc::unbounded();
        let core = ProviderCore::new(Some(return_tx));
        let callbacks = Mutex::new(HashMap::new());
        let (callback_tx, callback_rx) = mpmc::unbounded();
        let provider = Self { core, callback_tx };
        let waker = CallbackHandlerWaker::new();
        let handler = CallbackHandler {
            return_rx,
            callbacks,
            callback_rx,
            waker,
        };
        (provider, handler)
    }

    #[cfg(test)]
    pub(crate) fn provider_id(&self) -> u32 {
        self.core.provider_id()
    }

    fn send_usercall(&self, usercall: Usercall, callback: Option<Callback>) -> CancelHandle {
        let usercall = self.core.assign_id(usercall);
        if let Some(callback) = callback {
            self.callback_tx
                .send((usercall.id, callback))
                .expect("failed to send callback");
        }
        self.core.send_usercall(usercall)
    }
}

#[derive(Clone)]
pub struct CallbackHandlerWaker {
    rx: mpmc::Receiver<()>,
    tx: mpmc::Sender<()>,
}

impl CallbackHandlerWaker {
    fn new() -> Self {
        let (tx, rx) = mpmc::bounded(1);
        Self { tx, rx }
    }

    /// Interrupts the currently running or a future call to the related
    /// CallbackHandler's `poll()`.
    pub fn wake(&self) {
        let _ = self.tx.try_send(());
    }

    /// Clears the effect of a previous call to `self.wake()` that is not yet
    /// observed by `CallbackHandler::poll()`.
    pub fn clear(&self) {
        let _ = self.rx.try_recv();
    }
}

pub struct CallbackHandler {
    return_rx: mpmc::Receiver<Identified<Return>>,
    callbacks: Mutex<HashMap<u64, Callback>>,
    // This is used so that threads sending usercalls don't have to take the lock.
    callback_rx: mpmc::Receiver<(u64, Callback)>,
    waker: CallbackHandlerWaker,
}

impl CallbackHandler {
    const RECV_BATCH_SIZE: usize = 128;

    // Returns an object that can be used to interrupt a blocked `self.poll()`.
    pub fn waker(&self) -> CallbackHandlerWaker {
        self.waker.clone()
    }

    #[inline]
    fn recv_returns(&self, timeout: Option<Duration>, returns: &mut [Identified<Return>]) -> usize {
        let first = match timeout {
            None => mpmc::select! {
                recv(self.return_rx) -> res => res.ok(),
                recv(self.waker.rx) -> _res => return 0,
            },
            Some(timeout) => mpmc::select! {
                recv(self.return_rx) -> res => res.ok(),
                recv(self.waker.rx) -> _res => return 0,
                default(timeout) => return 0,
            },
        }
        .expect("return channel closed unexpectedly");
        let mut count = 0;
        for ret in std::iter::once(first).chain(self.return_rx.try_iter().take(returns.len() - 1)) {
            returns[count] = ret;
            count += 1;
        }
        count
    }

    /// Poll for returned usercalls and execute their respective callback
    /// functions. If `timeout` is `None`, it will block execution until at
    /// least one return is received, otherwise it will block until there is a
    /// return or timeout is elapsed. Returns the number of executed callbacks.
    /// This can be interrupted using `CallbackHandlerWaker::wake()`.
    pub fn poll(&self, timeout: Option<Duration>) -> usize {
        // 1. wait for returns
        let mut returns = [Identified::default(); Self::RECV_BATCH_SIZE];
        let returns = match self.recv_returns(timeout, &mut returns) {
            0 => return 0,
            n => &returns[..n],
        };
        // 2. try to lock the mutex, if successful, receive all pending callbacks and put them in the hash map
        let mut guard = match self.callbacks.try_lock() {
            Ok(mut callbacks) => {
                for (id, cb) in self.callback_rx.try_iter() {
                    callbacks.insert(id, cb);
                }
                callbacks
            }
            _ => self.callbacks.lock().unwrap(),
        };
        // 3. remove callbacks for returns received in step 1 from the hash map
        let mut ret_callbacks = Vec::with_capacity(returns.len());
        for ret in returns {
            let cb = guard.remove(&ret.id);
            ret_callbacks.push((ret, cb));
        }
        drop(guard);
        // 4. execute the callbacks without hugging the mutex
        let mut count = 0;
        for (ret, cb) in ret_callbacks {
            if let Some(cb) = cb {
                cb.call(ret.data);
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hacks::MakeSend;
    use crate::test_support::*;
    use crossbeam_channel as mpmc;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::os::fortanix_sgx::io::AsRawFd;
    use std::os::fortanix_sgx::usercalls::alloc::User;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn cancel_accept() {
        let provider = AutoPollingProvider::new();
        let port = 6688;
        let addr = format!("0.0.0.0:{}", port);
        let (tx, rx) = mpmc::bounded(1);
        provider.bind_stream(&addr, move |res| {
            tx.send(res).unwrap();
        });
        let bind_res = rx.recv().unwrap();
        let listener = bind_res.unwrap();
        let fd = listener.as_raw_fd();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count1 = Arc::clone(&accept_count);
        let (tx, rx) = mpmc::bounded(1);
        let accept = provider.accept_stream(fd, move |res| {
            if let Ok(_) = res {
                accept_count1.fetch_add(1, Ordering::Relaxed);
            }
            tx.send(()).unwrap();
        });
        accept.cancel();
        thread::sleep(Duration::from_millis(10));
        let _ = TcpStream::connect(&addr);
        let _ = rx.recv();
        assert_eq!(accept_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn connect() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let provider = AutoPollingProvider::new();
        let (tx, rx) = mpmc::bounded(1);
        provider.connect_stream(&addr, move |res| {
            tx.send(res).unwrap();
        });
        let res = rx.recv().unwrap();
        assert!(res.is_ok());
    }

    #[test]
    fn safe_alloc_free() {
        let provider = AutoPollingProvider::new();

        const LEN: usize = 64 * 1024;
        let (tx, rx) = mpmc::bounded(1);
        provider.alloc_slice::<u8, _>(LEN, move |res| {
            let buf = res.expect("failed to allocate memory");
            tx.send(MakeSend::new(buf)).unwrap();
        });
        let user_buf = rx.recv().unwrap().into_inner();
        assert_eq!(user_buf.len(), LEN);

        let (tx, rx) = mpmc::bounded(1);
        let cb = move || {
            tx.send(()).unwrap();
        };
        provider.free(user_buf, Some(cb));
        rx.recv().unwrap();
    }

    #[test]
    fn callback_handler_waker() {
        let (_provider, handler) = AsyncUsercallProvider::new();
        let waker = handler.waker();
        let (tx, rx) = mpmc::bounded(1);
        let h = thread::spawn(move || {
            let n1 = handler.poll(None);
            tx.send(()).unwrap();
            let n2 = handler.poll(Some(Duration::from_secs(3)));
            tx.send(()).unwrap();
            n1 + n2
        });
        for _ in 0..2 {
            waker.wake();
            rx.recv().unwrap();
        }
        assert_eq!(h.join().unwrap(), 0);
    }

    #[test]
    #[ignore]
    fn echo() {
        println!();
        let provider = Arc::new(AutoPollingProvider::new());
        const ADDR: &'static str = "0.0.0.0:7799";
        let (tx, rx) = mpmc::bounded(1);
        provider.bind_stream(ADDR, move |res| {
            tx.send(res).unwrap();
        });
        let bind_res = rx.recv().unwrap();
        let listener = bind_res.unwrap();
        println!("bind done: {:?}", listener);
        let fd = listener.as_raw_fd();
        let cb = KeepAccepting {
            listener,
            provider: Arc::clone(&provider),
        };
        provider.accept_stream(fd, cb);
        thread::sleep(Duration::from_secs(60));
    }

    struct KeepAccepting {
        listener: TcpListener,
        provider: Arc<AutoPollingProvider>,
    }

    impl FnOnce<(io::Result<TcpStream>,)> for KeepAccepting {
        type Output = ();

        extern "rust-call" fn call_once(self, args: (io::Result<TcpStream>,)) -> Self::Output {
            let res = args.0;
            println!("accept result: {:?}", res);
            if let Ok(stream) = res {
                let fd = stream.as_raw_fd();
                let cb = Echo {
                    stream,
                    read: true,
                    provider: self.provider.clone(),
                };
                self.provider
                    .read(fd, User::<[u8]>::uninitialized(Echo::READ_BUF_SIZE), cb);
            }
            let provider = Arc::clone(&self.provider);
            provider.accept_stream(self.listener.as_raw_fd(), self);
        }
    }

    struct Echo {
        stream: TcpStream,
        read: bool,
        provider: Arc<AutoPollingProvider>,
    }

    impl Echo {
        const READ_BUF_SIZE: usize = 1024;

        fn close(self) {
            let fd = self.stream.as_raw_fd();
            println!("connection closed, fd = {}", fd);
            self.provider.close(fd, None::<Box<dyn FnOnce() + Send>>);
        }
    }

    // read callback
    impl FnOnce<(io::Result<usize>, User<[u8]>)> for Echo {
        type Output = ();

        extern "rust-call" fn call_once(mut self, args: (io::Result<usize>, User<[u8]>)) -> Self::Output {
            let (res, user) = args;
            assert!(self.read);
            match res {
                Ok(len) if len > 0 => {
                    self.read = false;
                    let provider = Arc::clone(&self.provider);
                    provider.write(self.stream.as_raw_fd(), (user, 0..len).into(), self);
                }
                _ => self.close(),
            }
        }
    }

    // write callback
    impl FnOnce<(io::Result<usize>, UserBuf)> for Echo {
        type Output = ();

        extern "rust-call" fn call_once(mut self, args: (io::Result<usize>, UserBuf)) -> Self::Output {
            let (res, _) = args;
            assert!(!self.read);
            match res {
                Ok(len) if len > 0 => {
                    self.read = true;
                    let provider = Arc::clone(&self.provider);
                    provider.read(
                        self.stream.as_raw_fd(),
                        User::<[u8]>::uninitialized(Echo::READ_BUF_SIZE),
                        self,
                    );
                }
                _ => self.close(),
            }
        }
    }
}
