#![feature(sgx_platform)]
#![feature(never_type)]
#![cfg_attr(test, feature(unboxed_closures))]
#![cfg_attr(test, feature(fn_traits))]

use crossbeam_channel as mpmc;
use ipc_queue::Identified;
use std::collections::HashMap;
use std::os::fortanix_sgx::usercalls::raw::UsercallNrs;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

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
/// retrieved on a dedicated thread. Users are notified of the results through
/// callback functions.
///
/// Users of this type should take care not to block execution in callbacks.
/// Ceratin usercalls can be cancelled through a handle, but note that it is
/// still possible to receive successful results for cancelled usercalls.
pub struct AsyncUsercallProvider {
    core: ProviderCore,
    callback_tx: mpmc::Sender<(u64, Callback)>,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

impl AsyncUsercallProvider {
    pub fn new() -> Self {
        let (return_tx, return_rx) = mpmc::unbounded();
        let core = ProviderCore::new(Some(return_tx));
        let (callback_tx, callback_rx) = mpmc::unbounded();
        let shutdown = Arc::new(AtomicBool::new(false));
        let callback_handler = CallbackHandler {
            return_rx,
            callback_rx,
            shutdown: Arc::clone(&shutdown),
        };
        let join_handle = thread::spawn(move || callback_handler.run());
        Self {
            core,
            callback_tx,
            shutdown,
            join_handle: Some(join_handle),
        }
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

impl Drop for AsyncUsercallProvider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // send a usercall to ensure CallbackHandler wakes up and breaks its loop.
        let u = Usercall(UsercallNrs::insecure_time as _, 0, 0, 0, 0);
        self.send_usercall(u, None);
        let join_handle = self.join_handle.take().unwrap();
        join_handle.join().unwrap();
    }
}

struct CallbackHandler {
    return_rx: mpmc::Receiver<Identified<Return>>,
    callback_rx: mpmc::Receiver<(u64, Callback)>,
    shutdown: Arc<AtomicBool>,
}

impl CallbackHandler {
    const BATCH: usize = 1024;

    fn recv_returns(&self) -> ([Identified<Return>; Self::BATCH], usize) {
        let first = self.return_rx.recv().expect("channel closed unexpectedly");
        let mut returns = [Identified {
            id: 0,
            data: Return(0, 0),
        }; Self::BATCH];
        let mut count = 0;
        for ret in std::iter::once(first).chain(self.return_rx.try_iter().take(Self::BATCH - 1)) {
            returns[count] = ret;
            count += 1;
        }
        (returns, count)
    }

    fn run(self) {
        let mut callbacks = HashMap::with_capacity(256);
        loop {
            // block until there are some returns
            let (returns, count) = self.recv_returns();
            // receive pending callbacks
            for (id, callback) in self.callback_rx.try_iter() {
                callbacks.insert(id, callback);
            }
            for ret in &returns[..count] {
                if let Some(cb) = callbacks.remove(&ret.id) {
                    let _r = panic::catch_unwind(panic::AssertUnwindSafe(move || {
                        cb.call(ret.data);
                    }));
                    // if let Err(e) = _r {
                    //     let msg = e
                    //         .downcast_ref::<String>()
                    //         .map(String::as_str)
                    //         .or_else(|| e.downcast_ref::<&str>().map(|&s| s));
                    //     println!("callback paniced: {:?}", msg);
                    // }
                }
            }
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
        }
    }
}
