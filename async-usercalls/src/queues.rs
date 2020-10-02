use crate::hacks::{alloc_descriptor, async_queues, to_enclave, Cancel, Return, Usercall};
use crossbeam_channel as mpmc;
use fortanix_sgx_abi::{EV_CANCELQ_NOT_FULL, EV_RETURNQ_NOT_EMPTY, EV_USERCALLQ_NOT_FULL};
use ipc_queue::{self, Identified, QueueEvent, RecvError, SynchronizationError, Synchronizer};
use lazy_static::lazy_static;
use std::os::fortanix_sgx::usercalls::raw;
use std::sync::{Arc, Mutex};
use std::{io, iter, thread};

pub(crate) type Sender<T> = ipc_queue::Sender<T, QueueSynchronizer>;
pub(crate) type Receiver<T> = ipc_queue::Receiver<T, QueueSynchronizer>;

pub(crate) struct Providers {
    usercall_queue_tx: Sender<Usercall>,
    cancel_queue_tx: Sender<Cancel>,
    provider_map: Arc<Mutex<Map<Option<mpmc::Sender<Identified<Return>>>>>>,
}

impl Providers {
    pub(crate) fn new_provider(
        &self,
        return_tx: Option<mpmc::Sender<Identified<Return>>>,
    ) -> (Sender<Usercall>, Sender<Cancel>, u32) {
        let id = self.provider_map.lock().unwrap().insert(return_tx);
        let usercall_queue_tx = self.usercall_queue_tx.clone();
        let cancel_queue_tx = self.cancel_queue_tx.clone();
        (usercall_queue_tx, cancel_queue_tx, id)
    }

    pub(crate) fn remove_provider(&self, id: u32) {
        let entry = self.provider_map.lock().unwrap().remove(id);
        assert!(entry.is_some());
    }
}

lazy_static! {
    pub(crate) static ref PROVIDERS: Providers = {
        let (utx, ctx, rx) = init_async_queues().expect("Failed to initialize async queues");
        let provider_map = Arc::new(Mutex::new(Map::new()));
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
    // FIXME: this is just a hack. Replace these with `User::<FifoDescriptor<T>>::uninitialized().into_raw()`
    let usercall_q = unsafe { alloc_descriptor::<Usercall>() };
    let cancel_q = unsafe { alloc_descriptor::<Cancel>() };
    let return_q = unsafe { alloc_descriptor::<Return>() };

    let r = unsafe { async_queues(usercall_q, return_q, cancel_q) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }

    // FIXME: this is another hack, replace with `unsafe { User::<FifoDescriptor<T>>::from_raw(q) }.to_enclave()`
    let usercall_queue = unsafe { to_enclave(usercall_q) };
    let cancel_queue = unsafe { to_enclave(cancel_q) };
    let return_queue = unsafe { to_enclave(return_q) };

    let utx = unsafe { Sender::from_descriptor(usercall_queue, QueueSynchronizer { queue: Queue::Usercall }) };
    let ctx = unsafe { Sender::from_descriptor(cancel_queue, QueueSynchronizer { queue: Queue::Cancel }) };
    let rx = unsafe { Receiver::from_descriptor(return_queue, QueueSynchronizer { queue: Queue::Return }) };
    Ok((utx, ctx, rx))
}

struct ReturnHandler {
    return_queue_rx: Receiver<Return>,
    provider_map: Arc<Mutex<Map<Option<mpmc::Sender<Identified<Return>>>>>>,
}

impl ReturnHandler {
    const N: usize = 1024;

    fn send(&self, returns: &[Identified<Return>]) {
        // This should hold the lock only for a short amount of time
        // since mpmc::Sender::send() will not block (unbounded channel).
        // Also note that the lock is uncontested most of the time, so
        // taking the lock should be fast.
        let provider_map = self.provider_map.lock().unwrap();
        for ret in returns {
            let provider_id = (ret.id >> 32) as u32;
            if let Some(sender) = provider_map.get(provider_id).and_then(|entry| entry.as_ref()) {
                let _ = sender.send(*ret);
            }
        }
    }

    fn run(self) {
        const DEFAULT_RETURN: Identified<Return> = Identified {
            id: 0,
            data: Return(0, 0),
        };
        loop {
            let mut returns = [DEFAULT_RETURN; Self::N];
            let first = match self.return_queue_rx.recv() {
                Ok(ret) => ret,
                Err(RecvError::Closed) => break,
            };
            let mut count = 0;
            for ret in iter::once(first).chain(self.return_queue_rx.try_iter().take(Self::N - 1)) {
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

use self::map::Map;
mod map {
    use fnv::FnvHashMap;

    pub struct Map<T> {
        map: FnvHashMap<u32, T>,
        next_id: u32,
    }

    impl<T> Map<T> {
        pub fn new() -> Self {
            Self {
                map: FnvHashMap::with_capacity_and_hasher(16, Default::default()),
                next_id: 0,
            }
        }

        pub fn insert(&mut self, value: T) -> u32 {
            let id = self.next_id;
            self.next_id += 1;
            let old = self.map.insert(id, value);
            debug_assert!(old.is_none());
            id
        }

        pub fn get(&self, id: u32) -> Option<&T> {
            self.map.get(&id)
        }

        pub fn remove(&mut self, id: u32) -> Option<T> {
            self.map.remove(&id)
        }
    }
}
