#![feature(sgx_platform)]
#![feature(never_type)]
#![cfg_attr(test, feature(unboxed_closures))]
#![cfg_attr(test, feature(fn_traits))]

use crossbeam_channel as mpmc;
use ipc_queue::Identified;
use std::collections::HashMap;
use std::panic;
use std::sync::Mutex;
use std::time::Duration;

mod alloc;
mod batch_drop;
mod callback;
mod duplicated;
mod hacks;
mod provider_api;
mod provider_core;
mod queues;
mod raw;
#[cfg(test)]
mod tests;

pub use self::alloc::{alloc_buf, alloc_byte_buffer, ReadBuffer, User, UserBuf, UserSafeExt, WriteBuffer};
pub use self::batch_drop::batch_drop;
pub use self::callback::CbFn;
pub use self::raw::RawApi;

use self::callback::*;
use self::hacks::{Cancel, Return, Usercall};
use self::provider_core::ProviderCore;
use self::queues::*;

pub struct CancelHandle<'p> {
    c: Identified<Cancel>,
    tx: &'p Sender<Cancel>,
}

impl<'p> CancelHandle<'p> {
    pub fn cancel(self) {
        self.tx.send(self.c).expect("failed to send cancellation");
    }

    pub(crate) fn new(c: Identified<Cancel>, tx: &'p Sender<Cancel>) -> Self {
        CancelHandle { c, tx }
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
        let handler = CallbackHandler {
            return_rx,
            callbacks,
            callback_rx,
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

pub struct CallbackHandler {
    return_rx: mpmc::Receiver<Identified<Return>>,
    callbacks: Mutex<HashMap<u64, Callback>>,
    // This is used so that threads sending usercalls don't have to take the lock.
    callback_rx: mpmc::Receiver<(u64, Callback)>,
}

impl CallbackHandler {
    #[inline]
    fn recv_returns(&self, timeout: Option<Duration>, returns: &mut [Identified<Return>]) -> usize {
        let first = match timeout {
            None => self.return_rx.recv().ok(),
            Some(timeout) => match self.return_rx.recv_timeout(timeout) {
                Ok(val) => Some(val),
                Err(mpmc::RecvTimeoutError::Disconnected) => None,
                Err(mpmc::RecvTimeoutError::Timeout) => return 0,
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
    pub fn poll(&self, timeout: Option<Duration>) -> usize {
        // 1. wait for returns
        let mut returns = [Identified {
            id: 0,
            data: Return(0, 0),
        }; 1024];
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
                let _r = panic::catch_unwind(panic::AssertUnwindSafe(move || {
                    cb.call(ret.data);
                }));
                count += 1;
                // if let Err(e) = _r {
                //     let msg = e
                //         .downcast_ref::<String>()
                //         .map(String::as_str)
                //         .or_else(|| e.downcast_ref::<&str>().map(|&s| s));
                //     println!("callback paniced: {:?}", msg);
                // }
            }
        }
        count
    }
}
