/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::atomic::Ordering;
use crate::AsyncReceiver;
use crate::AsyncSender;
use crate::AsyncSynchronizer;
#[cfg(not(target_env = "sgx"))]
use crate::DescriptorGuard;
use crate::Identified;
use crate::QueueEvent;
use crate::RecvError;
use crate::SendError;
use crate::SynchronizationError;
use crate::Transmittable;
use crate::TryRecvError;
use crate::TrySendError;
use crate::position::PositionMonitor;

unsafe impl<T: Send, S: Send> Send for AsyncSender<T, S> {}
unsafe impl<T: Send, S: Sync> Sync for AsyncSender<T, S> {}

impl<T, S: Clone> Clone for AsyncSender<T, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            synchronizer: self.synchronizer.clone(),
        }
    }
}

impl<T: Transmittable, S: AsyncSynchronizer> AsyncSender<T, S> {
    pub async fn send(&self, val: Identified<T>) -> Result<(), SendError> {
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
                        .wait(QueueEvent::NotFull).await
                        .map_err(|SynchronizationError::ChannelClosed| SendError::Closed)?;
                }
                Err(TrySendError::Closed) => return Err(SendError::Closed),
            };
        }
    }

    /// Consumes `self` and returns a DescriptorGuard.
    /// The returned guard can be used to make `FifoDescriptor`s that remain
    /// valid as long as the guard is not dropped.
    #[cfg(not(target_env = "sgx"))]
    pub fn into_descriptor_guard(self) -> DescriptorGuard<T> {
        self.inner.into_descriptor_guard()
    }
}

unsafe impl<T: Send, S: Send> Send for AsyncReceiver<T, S> {}

impl<T: Transmittable, S: AsyncSynchronizer> AsyncReceiver<T, S> {
    pub async fn recv(&self) -> Result<Identified<T>, RecvError> {
        loop {
            match self.inner.try_recv_impl() {
                Ok((val, wake_sender, read_wrapped_around)) => {
                    if wake_sender {
                        self.synchronizer.notify(QueueEvent::NotFull);
                    }
                    if read_wrapped_around {
                        self.read_epoch.fetch_add(1, Ordering::Relaxed);
                    }
                    return Ok(val);
                }
                Err(TryRecvError::QueueEmpty) => {
                    self.synchronizer
                        .wait(QueueEvent::NotEmpty).await
                        .map_err(|SynchronizationError::ChannelClosed| RecvError::Closed)?;
                }
                Err(TryRecvError::Closed) => return Err(RecvError::Closed),
            }
        }
    }

    pub fn position_monitor(&self) -> PositionMonitor<T> {
        PositionMonitor::new(self.read_epoch.clone(), self.inner.clone())
    }

    /// Consumes `self` and returns a DescriptorGuard.
    /// The returned guard can be used to make `FifoDescriptor`s that remain
    /// valid as long as the guard is not dropped.
    #[cfg(not(target_env = "sgx"))]
    pub fn into_descriptor_guard(self) -> DescriptorGuard<T> {
        self.inner.into_descriptor_guard()
    }
}

#[cfg(not(target_env = "sgx"))]
#[cfg(test)]
mod tests {
    use futures::future::FutureExt;
    use futures::lock::Mutex;
    use tokio::sync::broadcast;
    use tokio::sync::broadcast::error::{SendError, RecvError};

    use crate::*;
    use crate::test_support::TestValue;

    async fn do_single_sender(len: usize, n: u64) {
        let s = TestAsyncSynchronizer::new();
        let (tx, rx) = bounded_async(len, s);
        let local = tokio::task::LocalSet::new();

        let h1 = local.spawn_local(async move {
            for i in 0..n {
                tx.send(Identified { id: i + 1, data: TestValue(i) }).await.unwrap();
            }
        });

        let h2 = local.spawn_local(async move {
            for i in 0..n {
                let v = rx.recv().await.unwrap();
                assert_eq!(v.id, i + 1);
                assert_eq!(v.data.0, i);
            }
        });

        local.await;
        h1.await.unwrap();
        h2.await.unwrap();
    }

    #[tokio::test]
    async fn single_sender() {
        do_single_sender(4, 10).await;
        do_single_sender(1, 10).await;
        do_single_sender(32, 1024).await;
        do_single_sender(1024, 32).await;
    }

    async fn do_multi_sender(len: usize, n: u64, senders: u64) {
        let s = TestAsyncSynchronizer::new();
        let (tx, rx) = bounded_async(len, s);
        let mut handles = Vec::with_capacity(senders as _);
        let local = tokio::task::LocalSet::new();

        for t in 0..senders {
            let tx = tx.clone();
            handles.push(local.spawn_local(async move {
                for i in 0..n {
                    let id = t * n + i + 1;
                    tx.send(Identified { id, data: TestValue(i) }).await.unwrap();
                }
            }));
        }

        handles.push(local.spawn_local(async move {
            for _ in 0..(n * senders) {
                rx.recv().await.unwrap();
            }
        }));

        local.await;
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn multi_sender() {
        do_multi_sender(4, 10, 3).await;
        do_multi_sender(4, 1, 100).await;
        do_multi_sender(2, 10, 100).await;
        do_multi_sender(1024, 30, 100).await;
    }

    #[tokio::test]
    async fn positions() {
        const LEN: usize = 16;
        let s = TestAsyncSynchronizer::new();
        let (tx, rx) = bounded_async(LEN, s);
        let monitor = rx.position_monitor();
        let mut id = 1;

        let p0 = monitor.write_position();
        tx.send(Identified { id, data: TestValue(1) }).await.unwrap();
        let p1 = monitor.write_position();
        tx.send(Identified { id: id + 1, data: TestValue(2) }).await.unwrap();
        let p2 = monitor.write_position();
        tx.send(Identified { id: id + 2, data: TestValue(3) }).await.unwrap();
        let p3 = monitor.write_position();
        id += 3;
        assert!(monitor.read_position().is_past(&p0) == Some(false));
        assert!(monitor.read_position().is_past(&p1) == Some(false));
        assert!(monitor.read_position().is_past(&p2) == Some(false));
        assert!(monitor.read_position().is_past(&p3) == Some(false));

        rx.recv().await.unwrap();
        assert!(monitor.read_position().is_past(&p0) == Some(true));
        assert!(monitor.read_position().is_past(&p1) == Some(false));
        assert!(monitor.read_position().is_past(&p2) == Some(false));
        assert!(monitor.read_position().is_past(&p3) == Some(false));

        rx.recv().await.unwrap();
        assert!(monitor.read_position().is_past(&p0) == Some(true));
        assert!(monitor.read_position().is_past(&p1) == Some(true));
        assert!(monitor.read_position().is_past(&p2) == Some(false));
        assert!(monitor.read_position().is_past(&p3) == Some(false));

        rx.recv().await.unwrap();
        assert!(monitor.read_position().is_past(&p0) == Some(true));
        assert!(monitor.read_position().is_past(&p1) == Some(true));
        assert!(monitor.read_position().is_past(&p2) == Some(true));
        assert!(monitor.read_position().is_past(&p3) == Some(false));

        for i in 0..1000 {
            let n = 1 + (i % LEN);
            let p4 = monitor.write_position();
            for _ in 0..n {
                tx.send(Identified { id, data: TestValue(id) }).await.unwrap();
                id += 1;
            }
            let p5 = monitor.write_position();
            for _ in 0..n {
                rx.recv().await.unwrap();
                assert!(monitor.read_position().is_past(&p0) == Some(true));
                assert!(monitor.read_position().is_past(&p1) == Some(true));
                assert!(monitor.read_position().is_past(&p2) == Some(true));
                assert!(monitor.read_position().is_past(&p3) == Some(true));
                assert!(monitor.read_position().is_past(&p4) == Some(true));
                assert!(monitor.read_position().is_past(&p5) == Some(false));
            }
        }
    }

    struct Subscription<T> {
        tx: broadcast::Sender<T>,
        rx: Mutex<broadcast::Receiver<T>>,
    }

    impl<T: Clone> Subscription<T> {
        fn new(capacity: usize) -> Self {
            let (tx, rx) = broadcast::channel(capacity);
            Self {
                tx,
                rx: Mutex::new(rx),
            }
        }

        fn send(&self, val: T) -> Result<(), SendError<T>> {
            self.tx.send(val).map(|_| ())
        }

        async fn recv(&self) -> Result<T, RecvError> {
            let mut rx = self.rx.lock().await;
            rx.recv().await
        }
    }

    impl<T> Clone for Subscription<T> {
        fn clone(&self) -> Self {
            Self {
                tx: self.tx.clone(),
                rx: Mutex::new(self.tx.subscribe()),
            }
        }
    }

    #[derive(Clone)]
    struct TestAsyncSynchronizer {
        not_empty: Subscription<()>,
        not_full: Subscription<()>,
    }

    impl TestAsyncSynchronizer {
        fn new() -> Self {
            Self {
                not_empty: Subscription::new(128),
                not_full: Subscription::new(128),
            }
        }
    }

    impl AsyncSynchronizer for TestAsyncSynchronizer {
        fn wait(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output=Result<(), SynchronizationError>> + '_>> {
            async move {
                match event {
                    QueueEvent::NotEmpty => self.not_empty.recv().await,
                    QueueEvent::NotFull => self.not_full.recv().await,
                }.map_err(|_| SynchronizationError::ChannelClosed)
            }.boxed()
        }

        fn notify(&self, event: QueueEvent) {
            let _ = match event {
                QueueEvent::NotEmpty => self.not_empty.send(()),
                QueueEvent::NotFull => self.not_full.send(()),
            };
        }
    }
}
