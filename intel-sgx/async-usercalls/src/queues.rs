use crate::provider_core::ProviderId;
use crossbeam_channel as mpmc;
use fortanix_sgx_abi::{EV_CANCELQ_NOT_FULL, EV_RETURNQ_NOT_EMPTY, EV_USERCALLQ_NOT_FULL};
use ipc_queue::{Identified, QueueEvent, RecvError, SynchronizationError, Synchronizer};
use lazy_static::lazy_static;
use std::os::fortanix_sgx::usercalls::alloc::User;
use std::os::fortanix_sgx::usercalls::raw::{
    self, async_queues, Cancel, FifoDescriptor, Return, Usercall,
};
use std::sync::{Arc, Mutex};
use std::{io, iter, thread};
use self::map::SequentialMap;

pub(crate) type Sender<T> = ipc_queue::Sender<T, QueueSynchronizer>;
pub(crate) type Receiver<T> = ipc_queue::Receiver<T, QueueSynchronizer>;

pub(crate) struct Providers {
    usercall_queue_tx: Sender<Usercall>,
    cancel_queue_tx: Sender<Cancel>,
    provider_map: Arc<Mutex<SequentialMap<Option<mpmc::Sender<Identified<Return>>>>>>,
}

impl Providers {
    pub(crate) fn new_provider(&self, return_tx: Option<mpmc::Sender<Identified<Return>>>) -> u32 {
        self.provider_map.lock().unwrap().insert(return_tx)
    }

    pub(crate) fn remove_provider(&self, id: u32) {
        let entry = self.provider_map.lock().unwrap().remove(id);
        assert!(entry.is_some());
    }

    pub(crate) fn usercall_sender(&self) -> &Sender<Usercall> {
        &self.usercall_queue_tx
    }

    pub(crate) fn cancel_sender(&self) -> &Sender<Cancel> {
        &self.cancel_queue_tx
    }
}

lazy_static! {
    pub(crate) static ref PROVIDERS: Providers = {
        let (utx, ctx, rx) = init_async_queues().expect("Failed to initialize async queues");
        let provider_map = Arc::new(Mutex::new(SequentialMap::new()));
        let return_handler = ReturnHandler {
            return_queue_rx: rx,
            provider_map: Arc::clone(&provider_map),
        };
        thread::spawn(move || return_handler.run());
        Providers {
            usercall_queue_tx: utx,
            cancel_queue_tx: ctx,
            provider_map,
        }
    };
}

fn init_async_queues() -> io::Result<(Sender<Usercall>, Sender<Cancel>, Receiver<Return>)> {
    let usercall_q = User::<FifoDescriptor<Usercall>>::uninitialized().into_raw();
    let cancel_q = User::<FifoDescriptor<Cancel>>::uninitialized().into_raw();
    let return_q = User::<FifoDescriptor<Return>>::uninitialized().into_raw();

    let r = unsafe { async_queues(usercall_q, return_q, cancel_q) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }

    let usercall_queue = unsafe { User::<FifoDescriptor<Usercall>>::from_raw(usercall_q) }.to_enclave();
    let cancel_queue = unsafe { User::<FifoDescriptor<Cancel>>::from_raw(cancel_q) }.to_enclave();
    let return_queue = unsafe { User::<FifoDescriptor<Return>>::from_raw(return_q) }.to_enclave();

    // FIXME: once `WithId` is exported from `std::os::fortanix_sgx::usercalls::raw`, we can remove
    // `transmute` calls here and use FifoDescriptor/WithId from std everywhere including in ipc-queue.
    // See: https://github.com/fortanix/rust-sgx/issues/533
    let utx = unsafe { Sender::from_descriptor(std::mem::transmute(usercall_queue), QueueSynchronizer { queue: Queue::Usercall }) };
    let ctx = unsafe { Sender::from_descriptor(std::mem::transmute(cancel_queue), QueueSynchronizer { queue: Queue::Cancel }) };
    let rx = unsafe { Receiver::from_descriptor(std::mem::transmute(return_queue), QueueSynchronizer { queue: Queue::Return }) };
    Ok((utx, ctx, rx))
}

struct ReturnHandler {
    return_queue_rx: Receiver<Return>,
    provider_map: Arc<Mutex<SequentialMap<Option<mpmc::Sender<Identified<Return>>>>>>,
}

impl ReturnHandler {
    const RECV_BATCH_SIZE: usize = 1024;

    fn send(&self, returns: &[Identified<Return>]) {
        // This should hold the lock only for a short amount of time
        // since mpmc::Sender::send() will not block (unbounded channel).
        // Also note that the lock is uncontested most of the time, so
        // taking the lock should be fast.
        let provider_map = self.provider_map.lock().unwrap();
        for ret in returns {
            // NOTE: some providers might decide not to receive results of usercalls they send
            // because the results are not interesting, e.g. BatchDropProvider.
            if let Some(sender) = provider_map.get(ret.provider_id()).and_then(|entry| entry.as_ref()) {
                let _ = sender.send(*ret);
            }
        }
    }

    fn run(self) {
        let mut returns = [Identified::default(); Self::RECV_BATCH_SIZE];
        loop {
            // Block until there is a return. Then we receive any other values
            // from the return queue **without** blocking using `try_iter()`.
            let first = match self.return_queue_rx.recv() {
                Ok(ret) => ret,
                Err(RecvError::Closed) => break,
            };
            let mut count = 0;
            for ret in iter::once(first).chain(self.return_queue_rx.try_iter().take(Self::RECV_BATCH_SIZE - 1)) {
                assert!(ret.id != 0);
                returns[count] = ret;
                count += 1;
            }
            self.send(&returns[..count]);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Queue {
    Usercall,
    Return,
    Cancel,
}

#[derive(Clone, Debug)]
pub(crate) struct QueueSynchronizer {
    queue: Queue,
}

impl Synchronizer for QueueSynchronizer {
    fn wait(&self, event: QueueEvent) -> Result<(), SynchronizationError> {
        let ev = match (self.queue, event) {
            (Queue::Usercall, QueueEvent::NotEmpty) => panic!("enclave should not recv on usercall queue"),
            (Queue::Cancel, QueueEvent::NotEmpty) => panic!("enclave should not recv on cancel queue"),
            (Queue::Return, QueueEvent::NotFull) => panic!("enclave should not send on return queue"),
            (Queue::Usercall, QueueEvent::NotFull) => EV_USERCALLQ_NOT_FULL,
            (Queue::Cancel, QueueEvent::NotFull) => EV_CANCELQ_NOT_FULL,
            (Queue::Return, QueueEvent::NotEmpty) => EV_RETURNQ_NOT_EMPTY,
        };
        unsafe {
            raw::wait(ev, raw::WAIT_INDEFINITE);
        }
        Ok(())
    }

    fn notify(&self, _event: QueueEvent) {
        // any synchronous usercall would do
        unsafe {
            raw::wait(0, raw::WAIT_NO);
        }
    }
}

mod map {
    use fnv::FnvHashMap;

    pub struct SequentialMap<T> {
        map: FnvHashMap<u32, T>,
        next_id: u32,
    }

    impl<T> SequentialMap<T> {
        pub fn new() -> Self {
            Self {
                map: FnvHashMap::with_capacity_and_hasher(16, Default::default()),
                next_id: 0,
            }
        }

        /// Insert a new value and return the index.
        ///
        /// # Panics
        /// Panics if `u32::MAX` entries are kept in the queue and a new one is attempted
        /// to be inserted. Note that removing entries from the queue also frees up space
        /// and the number of available entries.
        pub fn insert(&mut self, value: T) -> u32 {
            let initial_id = self.next_id;
            loop {
                let id = self.next_id;
                // We intentionally ignore the overflow here, thus allowing `next_id` to jump back to 0
                // after `u32::MAX` number of insertions.
                // TODO: We should have a way of limiting the size of this queue to avoid
                //   potentially checking 2^32 items and huge memory consumption
                //   https://github.com/fortanix/rust-sgx/issues/550
                self.next_id = self.next_id.overflowing_add(1).0;
                if !self.map.contains_key(&id) {
                    self.map.insert(id, value);
                    return id
                } else if id == initial_id {
                    panic!("Cannot keep more than {} entries into the async queue. Aborting.", u32::MAX)
                } else {
                    continue
                }
            }
        }

        pub fn get(&self, id: u32) -> Option<&T> {
            self.map.get(&id)
        }

        pub fn remove(&mut self, id: u32) -> Option<T> {
            self.map.remove(&id)
        }
    }
}
