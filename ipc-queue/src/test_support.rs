/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct TestValue {
    id: AtomicU64,
    val: u64,
}

impl TestValue {
    pub fn new(id: u64, val: u64) -> Self {
        Self {
            id: AtomicU64::new(id),
            val,
        }
    }

    pub fn get_val(&self) -> u64 {
        self.val
    }
}

impl WithAtomicId for TestValue {
    fn empty() -> Self {
        Self::new(0, 0)
    }
    fn get_id(&self) -> u64 {
        self.id.load(Ordering::SeqCst)
    }
    fn set_id(&mut self, id: u64) {
        self.id.store(id, Ordering::SeqCst);
    }
    fn copy_except_id(&mut self, from: &Self) {
        let Self { id: _, val } = from;
        self.val = *val;
    }
}

#[derive(Clone)]
pub struct NoopSynchronizer;

impl Synchronizer for NoopSynchronizer {
    fn wait(&self, _event: QueueEvent) -> Result<(), SynchronizationError> { Ok(()) }
    fn notify(&self, _event: QueueEvent) { }
}

// A publisher/subscriber channel implementation
pub mod pubsub {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};

    pub struct Channel<T> {
        inner: Arc<ChannelInner<T>>,
    }

    pub struct Subscription<T> {
        receiver: mpsc::Receiver<T>,
        inner: Arc<ChannelInner<T>>,
        id: usize,
    }

    struct ChannelInner<T> {
        senders: Mutex<HashMap<usize, mpsc::Sender<T>>>,
        last_id: AtomicUsize,
    }

    impl<T: Clone> ChannelInner<T> {
        // the lock is held for a short duration since mpsc::Sender<T>::send() never blocks.
        fn broadcast(&self, msg: T) -> Result<(), mpsc::SendError<T>> {
            let senders = self.senders.lock().unwrap();
            for (_, sender) in senders.iter() {
                match sender.send(msg.clone()) {
                    Ok(_) => {}
                    Err(err) => return Err(err),
                }
            }
            Ok(())
        }

        fn subscribe(self: Arc<Self>) -> Subscription<T> {
            let id = self.last_id.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = mpsc::channel();
            {
                let mut senders = self.senders.lock().unwrap();
                assert!(senders.insert(id, tx).is_none());
            }
            Subscription {
                receiver: rx,
                inner: self,
                id,
            }
        }
    }

    impl<T: Clone> Channel<T> {
        pub fn new() -> Self {
            Self {
                inner: Arc::new(ChannelInner {
                    senders: Mutex::new(HashMap::new()),
                    last_id: AtomicUsize::new(0),
                }),
            }
        }

        #[allow(unused)]
        pub fn broadcast(&self, msg: T) -> Result<(), mpsc::SendError<T>> {
            self.inner.broadcast(msg)
        }

        pub fn subscribe(&self) -> Subscription<T> {
            self.inner.clone().subscribe()
        }
    }

    impl<T: Clone> Subscription<T> {
        // blocks current thread until a message is received or hangup.
        pub fn recv(&self) -> Result<T, mpsc::RecvError> {
            self.receiver.recv()
        }

        pub fn broadcast(&self, msg: T) -> Result<(), mpsc::SendError<T>> {
            self.inner.broadcast(msg)
        }
    }

    impl<T> Drop for Subscription<T> {
        fn drop(&mut self) {
            let mut senders = self.inner.senders.lock().unwrap();
            senders.remove(&self.id);
        }
    }

    impl<T: Clone> Clone for Subscription<T> {
        fn clone(&self) -> Self {
            self.inner.clone().subscribe()
        }
    }
}
