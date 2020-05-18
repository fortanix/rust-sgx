/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use crate::fifo::*;
use fortanix_sgx_abi::FifoDescriptor;

unsafe impl<T: Send, S: Send> Send for Sender<T, S> {}
unsafe impl<T: Send, S: Sync> Sync for Sender<T, S> {}

impl<T, S: Clone> Clone for Sender<T, S> {
    fn clone(&self) -> Self {
        Self {
            descriptor: self.descriptor.clone(),
            synchronizer: self.synchronizer.clone(),
        }
    }
}

impl<T: WithAtomicId, S: Synchronizer> Sender<T, S> {
    pub fn new(descriptor: FifoDescriptor<T>, synchronizer: S) -> Self {
        Self {
            descriptor,
            synchronizer,
        }
    }

    pub fn try_send(&self, val: &T) -> Result<(), TrySendError> {
        try_send_impl(&self.descriptor, val).map(|wake_receiver| {
            if wake_receiver {
                self.synchronizer.notify(QueueEvent::NotEmpty);
            }
        })
    }

    pub fn send(&self, val: &T) -> Result<(), SendError> {
        loop {
            match try_send_impl(&self.descriptor, val) {
                Ok(wake_receiver) => {
                    if wake_receiver {
                        self.synchronizer.notify(QueueEvent::NotEmpty);
                    }
                    return Ok(());
                }
                Err(TrySendError::QueueFull) => {
                    self.synchronizer
                        .wait(QueueEvent::NotFull)
                        .map_err(|SynchronizationError::ChannelClosed| SendError::Closed)?;
                }
            }
        }
    }
}

unsafe impl<T: Send, S: Send> Send for Receiver<T, S> {}

impl<T: WithAtomicId, S: Synchronizer> Receiver<T, S> {
    /// Panics if there is an existing (sync or async) receiver for the same queue.
    pub fn new(descriptor: FifoDescriptor<T>, synchronizer: S) -> Self {
        RECEIVER_TRACKER.new_receiver(descriptor.data as usize);
        Self {
            descriptor,
            synchronizer,
        }
    }

    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        try_recv_impl(&self.descriptor).map(|(val, wake_sender)| {
            if wake_sender {
                self.synchronizer.notify(QueueEvent::NotFull);
            }
            val
        })
    }

    pub fn try_iter(&self) -> TryIter<'_, T, S> {
        TryIter(self)
    }

    pub fn recv(&self) -> Result<T, RecvError> {
        loop {
            match try_recv_impl(&self.descriptor) {
                Ok((val, wake_sender)) => {
                    if wake_sender {
                        self.synchronizer.notify(QueueEvent::NotFull);
                    }
                    return Ok(val);
                }
                Err(TryRecvError::QueueEmpty) => {
                    self.synchronizer
                        .wait(QueueEvent::NotEmpty)
                        .map_err(|SynchronizationError::ChannelClosed| RecvError::Closed)?;
                }
            }
        }
    }
}

impl<T, S> Drop for Receiver<T, S> {
    fn drop(&mut self) {
        RECEIVER_TRACKER.drop_receiver(self.descriptor.data as usize);
    }
}

pub struct TryIter<'r, T, S>(&'r Receiver<T, S>);

impl<'r, T: WithAtomicId, S: Synchronizer> Iterator for TryIter<'r, T, S> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pubsub::{Channel, Subscription};
    use crate::test_support::*;
    use std::thread;

    fn do_single_sender(len: usize, n: u64) {
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(len);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);

        let h = thread::spawn(move || {
            for i in 0..n {
                tx.send(&TestValue::new(i + 1, i)).unwrap();
            }
        });

        for i in 0..n {
            let v = rx.recv().unwrap();
            assert_eq!(v.get_id(), i + 1);
            assert_eq!(v.get_val(), i);
        }

        h.join().unwrap();
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn single_sender() {
        do_single_sender(4, 10);
        do_single_sender(1, 10);
        do_single_sender(32, 1024);
        do_single_sender(1024, 32);
    }

    fn do_multi_sender(len: usize, n: u64, senders: u64) {
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(len);
        let rx = fifo.receiver(s.clone());
        let mut handles = Vec::with_capacity(senders as _);

        for t in 0..senders {
            let tx = fifo.sender(s.clone());
            handles.push(thread::spawn(move || {
                for i in 0..n {
                    let id = t * n + i + 1;
                    tx.send(&TestValue::new(id, i)).unwrap();
                }
            }));
        }

        for _ in 0..(n * senders) {
            rx.recv().unwrap();
        }

        for h in handles {
            h.join().unwrap();
        }
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn multi_sender() {
        do_multi_sender(4, 10, 3);
        do_multi_sender(4, 1, 100);
        do_multi_sender(2, 10, 100);
        do_multi_sender(1024, 30, 100);
    }

    #[test]
    fn try_error() {
        const N: u64 = 8;
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(N as _);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);

        for i in 0..N {
            tx.send(&TestValue::new(i + 1, i)).unwrap();
        }
        assert!(tx.try_send(&TestValue::new(N + 1, N)).is_err());

        for i in 0..N {
            let v = rx.recv().unwrap();
            assert_eq!(v.get_id(), i + 1);
            assert_eq!(v.get_val(), i);
        }
        assert!(rx.try_recv().is_err());

        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn very_optimistic() {
        const N: u64 = 8;
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(N as _);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);

        for i in 0..N {
            tx.try_send(&TestValue::new(i + 1, i)).unwrap();
        }

        for i in 0..N {
            let v = rx.try_recv().unwrap();
            assert_eq!(v.get_id(), i + 1);
            assert_eq!(v.get_val(), i);
        }

        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn mixed_try_send() {
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(8);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);

        let h = thread::spawn(move || {
            let mut sent_without_wait = 0;
            for _ in 0..7 {
                for i in 0..11 {
                    let v = TestValue::new(i + 1, i);
                    if tx.try_send(&v).is_err() {
                        tx.send(&v).unwrap();
                    } else {
                        sent_without_wait += 1;
                    }
                }
            }
            assert!(sent_without_wait > 0);
        });

        for _ in 0..7 {
            for i in 0..11 {
                let v = rx.recv().unwrap();
                assert_eq!(v.get_id(), i + 1);
                assert_eq!(v.get_val(), i);
            }
        }

        h.join().unwrap();
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn mixed_try_recv() {
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(8);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);

        let h = thread::spawn(move || {
            for _ in 0..11 {
                for i in 0..13 {
                    tx.send(&TestValue::new(i + 1, i)).unwrap();
                }
            }
        });

        for _ in 0..11 {
            for i in 0..13 {
                let v = match rx.try_recv() {
                    Ok(v) => v,
                    Err(_) => rx.recv().unwrap(),
                };
                assert_eq!(v.get_id(), i + 1);
                assert_eq!(v.get_val(), i);
            }
        }

        h.join().unwrap();
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn try_iter() {
        let s = TestSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(8);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s);
        const N: u64 = 2048;

        let h = thread::spawn(move || {
            for i in 0..N {
                tx.send(&TestValue::new(i + 1, i)).unwrap();
            }
        });

        let mut total = 0;
        while total < N {
            for v in rx.recv().ok().into_iter().chain(rx.try_iter()) {
                assert_eq!(v.get_id(), total + 1);
                assert_eq!(v.get_val(), total);
                total += 1;
            }
        }

        h.join().unwrap();
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[derive(Clone)]
    pub struct TestSynchronizer {
        not_empty: Subscription<()>,
        not_full: Subscription<()>,
    }

    impl TestSynchronizer {
        pub fn new() -> Self {
            Self {
                not_empty: Channel::new().subscribe(),
                not_full: Channel::new().subscribe(),
            }
        }
    }

    impl Synchronizer for TestSynchronizer {
        fn wait(&self, event: QueueEvent) -> Result<(), SynchronizationError> {
            match event {
                QueueEvent::NotEmpty => self.not_empty.recv(),
                QueueEvent::NotFull => self.not_full.recv(),
            }.map_err(|_| SynchronizationError::ChannelClosed)
        }

        fn notify(&self, event: QueueEvent) {
            let _ = match event {
                QueueEvent::NotEmpty => self.not_empty.broadcast(()),
                QueueEvent::NotFull => self.not_full.broadcast(()),
            };
        }
    }
}
