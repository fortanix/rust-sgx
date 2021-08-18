/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use fortanix_sgx_abi::FifoDescriptor;

use super::*;

unsafe impl<T: Send, S: Send> Send for Sender<T, S> {}
unsafe impl<T: Send, S: Sync> Sync for Sender<T, S> {}

impl<T, S: Clone> Clone for Sender<T, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            synchronizer: self.synchronizer.clone(),
        }
    }
}

impl<T: Transmittable, S: Synchronizer> Sender<T, S> {
    /// Create a `Sender` from a `FifoDescriptor` and `Synchronizer`.
    ///
    /// # Safety
    ///
    /// The caller must ensure the following:
    ///
    /// * The `data` and `len` fields in `FifoDescriptor` must adhere to all
    ///   safety requirements described in `std::slice::from_raw_parts_mut()`
    ///
    /// * The `offsets` field in `FifoDescriptor` must be non-null and point
    ///   to a valid memory location holding an `AtomicUsize`.
    ///
    /// * The synchronizer must somehow know how to correctly synchronize with
    ///   the other end of the channel.
    pub unsafe fn from_descriptor(d: FifoDescriptor<T>, synchronizer: S) -> Self {
        Self {
            inner: Fifo::from_descriptor(d),
            synchronizer,
        }
    }

    pub fn try_send(&self, val: Identified<T>) -> Result<(), TrySendError> {
        self.inner.try_send_impl(val).map(|wake_receiver| {
            if wake_receiver {
                self.synchronizer.notify(QueueEvent::NotEmpty);
            }
        })
    }

    /// Tries to send multiple values. Calling this function has the same
    /// semantics as calling `try_send` for each item in order until an error
    /// occurs, but it has the benefit of notifying the receiver at most once.
    ///
    /// Returns the number of successfully sent items if any item was
    /// successfully sent, otherwise returns an error.
    pub fn try_send_multiple(&self, values: &[Identified<T>]) -> Result<usize, TrySendError> {
        let mut wake_receiver = false;
        let mut sent = 0;
        for val in values {
            wake_receiver |= match self.inner.try_send_impl(*val) {
                Ok(wake_receiver) => wake_receiver,
                Err(e) if sent == 0 => return Err(e),
                Err(_) => break,
            };
            sent += 1;
        }
        if wake_receiver {
            self.synchronizer.notify(QueueEvent::NotEmpty);
        }
        Ok(sent)
    }

    pub fn send(&self, val: Identified<T>) -> Result<(), SendError> {
        loop {
            match self.inner.try_send_impl(val) {
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
                Err(TrySendError::Closed) => return Err(SendError::Closed),
            };
        }
    }
}

unsafe impl<T: Send, S: Send> Send for Receiver<T, S> {}

impl<T: Transmittable, S: Synchronizer> Receiver<T, S> {
    /// Create a `Receiver` from a `FifoDescriptor` and `Synchronizer`.
    ///
    /// # Safety
    ///
    /// In addition to all requirements laid out in `Sender::from_descriptor`,
    /// the caller must ensure the following additional requirements:
    ///
    /// * The caller must ensure that there is at most one `Receiver` for the queue.
    pub unsafe fn from_descriptor(d: FifoDescriptor<T>, synchronizer: S) -> Self {
        Self {
            inner: Fifo::from_descriptor(d),
            synchronizer,
        }
    }

    pub fn try_recv(&self) -> Result<Identified<T>, TryRecvError> {
        self.inner.try_recv_impl().map(|(val, wake_sender, _)| {
            if wake_sender {
                self.synchronizer.notify(QueueEvent::NotFull);
            }
            val
        })
    }

    pub fn try_iter(&self) -> TryIter<'_, T, S> {
        TryIter(self)
    }

    pub fn recv(&self) -> Result<Identified<T>, RecvError> {
        loop {
            match self.inner.try_recv_impl() {
                Ok((val, wake_sender, _)) => {
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
                Err(TryRecvError::Closed) => return Err(RecvError::Closed),
            }
        }
    }
}

pub struct TryIter<'r, T: 'static, S>(&'r Receiver<T, S>);

impl<'r, T: Transmittable, S: Synchronizer> Iterator for TryIter<'r, T, S> {
    type Item = Identified<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::pubsub::{Channel, Subscription};
    use crate::test_support::TestValue;
    use crate::*;
    use std::thread;

    fn do_single_sender(len: usize, n: u64) {
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(len, s);

        let h = thread::spawn(move || {
            for i in 0..n {
                tx.send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
            }
        });

        for i in 0..n {
            let v = rx.recv().unwrap();
            assert_eq!(v.id, i + 1);
            assert_eq!(v.data.0, i);
        }

        h.join().unwrap();
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
        let (tx, rx) = bounded(len, s);
        let mut handles = Vec::with_capacity(senders as _);

        for t in 0..senders {
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                for i in 0..n {
                    let id = t * n + i + 1;
                    tx.send(Identified { id, data: TestValue(i) }).unwrap();
                }
            }));
        }

        for _ in 0..(n * senders) {
            rx.recv().unwrap();
        }

        for h in handles {
            h.join().unwrap();
        }
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
        let (tx, rx) = bounded(N as _, s);

        for i in 0..N {
            tx.send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
        }
        assert!(tx.try_send(Identified { id: N + 1, data: TestValue(N) }).is_err());

        for i in 0..N {
            let v = rx.recv().unwrap();
            assert_eq!(v.id, i + 1);
            assert_eq!(v.data.0, i);
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn very_optimistic() {
        const N: u64 = 8;
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(N as _, s);

        for i in 0..N {
            tx.try_send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
        }

        for i in 0..N {
            let v = rx.try_recv().unwrap();
            assert_eq!(v.id, i + 1);
            assert_eq!(v.data.0, i);
        }
    }

    #[test]
    fn mixed_try_send() {
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(8, s);

        let h = thread::spawn(move || {
            let mut sent_without_wait = 0;
            for _ in 0..7 {
                for i in 0..11 {
                    let v = Identified { id: i + 1, data: TestValue(i) };
                    if let Err(_) = tx.try_send(v) {
                        tx.send(v).unwrap();
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
                assert_eq!(v.id, i + 1);
                assert_eq!(v.data.0, i);
            }
        }

        h.join().unwrap();
    }

    #[test]
    fn mixed_try_recv() {
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(8, s);

        let h = thread::spawn(move || {
            for _ in 0..11 {
                for i in 0..13 {
                    tx.send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
                }
            }
        });

        for _ in 0..11 {
            for i in 0..13 {
                let v = match rx.try_recv() {
                    Ok(v) => v,
                    Err(_) => rx.recv().unwrap(),
                };
                assert_eq!(v.id, i + 1);
                assert_eq!(v.data.0, i);
            }
        }

        h.join().unwrap();
    }

    #[test]
    fn try_iter() {
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(8, s);
        const N: u64 = 2048;

        let h = thread::spawn(move || {
            for i in 0..N {
                tx.send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
            }
        });

        let mut total = 0;
        while total < N {
            for v in rx.recv().ok().into_iter().chain(rx.try_iter()) {
                assert_eq!(v.id, total + 1);
                assert_eq!(v.data.0, total);
                total += 1;
            }
        }

        h.join().unwrap();
    }

    #[test]
    fn try_send_multiple() {
        let s = TestSynchronizer::new();
        let (tx, rx) = bounded(32, s);
        const SENDERS: usize = 4;
        const N: usize = 1024;
        let mut handles = Vec::with_capacity(SENDERS);

        for t in 0..SENDERS {
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                let mut to_send = Vec::with_capacity(N);
                for i in 0..N {
                    let id = (t * N + i + 1) as u64;
                    to_send.push(Identified { id, data: TestValue(i as u64) });
                }
                let mut sent = 0;
                while sent < to_send.len() {
                    match tx.try_send_multiple(&to_send[sent..]) {
                        Err(_) => thread::yield_now(),
                        Ok(n) => sent += n,
                    }
                }
            }));
        }

        let mut values = Vec::with_capacity(N * SENDERS);
        for _ in 0..(N * SENDERS) {
            values.push(rx.recv().unwrap());
        }
        values.sort_by_key(|v| v.id);
        assert!(values.windows(2).all(|w| w[0].id < w[1].id));

        for h in handles {
            h.join().unwrap();
        }
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
