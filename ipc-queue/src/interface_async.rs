/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use fortanix_sgx_abi::FifoDescriptor;

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

impl<T: Identified, S: AsyncSynchronizer> AsyncSender<T, S> {
    pub async fn send(&self, mut val: T) -> Result<(), SendError> {
        loop {
            val = match self.inner.try_send_impl(val) {
                Ok(wake_receiver) => {
                    if wake_receiver {
                        self.synchronizer.notify(QueueEvent::NotEmpty);
                    }
                    return Ok(());
                }
                Err((TrySendError::QueueFull, val)) => {
                    self.synchronizer
                        .wait(QueueEvent::NotFull).await
                        .map_err(|SynchronizationError::ChannelClosed| SendError::Closed)?;
                    val
                }
            };
        }
    }

    /// Consumes `self` and returns a FifoDescriptor.
    /// **NOTE:** this function leaks the internal storage to ensure that the
    /// pointers in the resulting descriptor remain valid.
    pub fn into_descriptor(self) -> FifoDescriptor<T> {
        self.inner.into_descriptor()
    }
}

unsafe impl<T: Send, S: Send> Send for AsyncReceiver<T, S> {}

impl<T: Identified, S: AsyncSynchronizer> AsyncReceiver<T, S> {
    pub async fn recv(&self) -> Result<T, RecvError> {
        loop {
            match self.inner.try_recv_impl() {
                Ok((val, wake_sender)) => {
                    if wake_sender {
                        self.synchronizer.notify(QueueEvent::NotFull);
                    }
                    return Ok(val);
                }
                Err(TryRecvError::QueueEmpty) => {
                    self.synchronizer
                        .wait(QueueEvent::NotEmpty).await
                        .map_err(|SynchronizationError::ChannelClosed| RecvError::Closed)?;
                }
            }
        }
    }

    /// Consumes `self` and returns a FifoDescriptor.
    /// **NOTE:** this function leaks the internal storage to ensure that the
    /// pointers in the resulting descriptor remain valid.
    pub fn into_descriptor(self) -> FifoDescriptor<T> {
        self.inner.into_descriptor()
    }
}

#[cfg(not(target_env = "sgx"))]
#[cfg(test)]
mod tests {
    use crate::*;
    use crate::test_support::*;
    use futures::future::FutureExt;
    use futures::lock::Mutex;
    use tokio::sync::broadcast as async_pubsub;

    async fn do_single_sender(len: usize, n: u64) {
        let s = TestAsyncSynchronizer::new();
        let (tx, rx) = bounded_async(len, s);
        let local = tokio::task::LocalSet::new();

        let h1 = local.spawn_local(async move {
            for i in 0..n {
                tx.send(TestValue { id: i + 1, val: i }).await.unwrap();
            }
        });

        let h2 = local.spawn_local(async move {
            for i in 0..n {
                let v = rx.recv().await.unwrap();
                assert_eq!(v.id, i + 1);
                assert_eq!(v.val, i);
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
                    tx.send(TestValue { id, val: i }).await.unwrap();
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

    struct Subscription<T> {
        tx: async_pubsub::Sender<T>,
        rx: Mutex<async_pubsub::Receiver<T>>,
    }

    impl<T: Clone> Subscription<T> {
        fn new(capacity: usize) -> Self {
            let (tx, rx) = async_pubsub::channel(capacity);
            Self {
                tx,
                rx: Mutex::new(rx),
            }
        }

        fn send(&self, val: T) -> Result<(), async_pubsub::SendError<T>> {
            self.tx.send(val).map(|_| ())
        }

        async fn recv(&self) -> Result<T, async_pubsub::RecvError> {
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
        fn wait(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output = Result<(), SynchronizationError>> + '_>> {
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
