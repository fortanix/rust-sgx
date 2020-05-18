/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use crate::fifo::*;
use fortanix_sgx_abi::FifoDescriptor;

unsafe impl<T: Send, S: Send> Send for AsyncSender<T, S> {}
unsafe impl<T: Send, S: Sync> Sync for AsyncSender<T, S> {}

impl<T, S: Clone> Clone for AsyncSender<T, S> {
    fn clone(&self) -> Self {
        Self {
            descriptor: self.descriptor.clone(),
            synchronizer: self.synchronizer.clone(),
        }
    }
}

impl<T: WithAtomicId, S: AsyncSynchronizer> AsyncSender<T, S> {
    pub fn new(descriptor: FifoDescriptor<T>, synchronizer: S) -> Self {
        Self {
            descriptor,
            synchronizer,
        }
    }

    pub async fn send(&self, val: &T) -> Result<(), SendError> {
        loop {
            match try_send_impl(&self.descriptor, val) {
                Ok(wake_receiver) => {
                    if wake_receiver {
                        self.synchronizer.notify(QueueEvent::NotEmpty).await;
                    }
                    return Ok(());
                }
                Err(TrySendError::QueueFull) => {
                    self.synchronizer
                        .wait(QueueEvent::NotFull).await
                        .map_err(|SynchronizationError::ChannelClosed| SendError::Closed)?;
                }
            }
        }
    }
}

unsafe impl<T: Send, S: Send> Send for AsyncReceiver<T, S> {}

impl<T: WithAtomicId, S: AsyncSynchronizer> AsyncReceiver<T, S> {
    /// Panics if there is an existing (sync or async) receiver for the same queue.
    pub fn new(descriptor: FifoDescriptor<T>, synchronizer: S) -> Self {
        RECEIVER_TRACKER.new_receiver(descriptor.data as usize);
        Self {
            descriptor,
            synchronizer,
        }
    }

    pub async fn recv(&self) -> Result<T, RecvError> {
        loop {
            match try_recv_impl(&self.descriptor) {
                Ok((val, wake_sender)) => {
                    if wake_sender {
                        self.synchronizer.notify(QueueEvent::NotFull).await;
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
}

impl<T, S> Drop for AsyncReceiver<T, S> {
    fn drop(&mut self) {
        RECEIVER_TRACKER.drop_receiver(self.descriptor.data as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use futures::future::FutureExt;
    use futures::lock::Mutex;
    use tokio::sync::broadcast as async_pubsub;

    async fn do_single_sender(len: usize, n: u64) {
        let s = TestAsyncSynchronizer::new();
        let mut fifo = Fifo::<TestValue>::new(len);
        let tx = fifo.async_sender(s.clone());
        let rx = fifo.async_receiver(s);
        let local = tokio::task::LocalSet::new();

        let h1 = local.spawn_local(async move {
            for i in 0..n {
                tx.send(&TestValue::new(i + 1, i)).await.unwrap();
            }
        });

        let h2 = local.spawn_local(async move {
            for i in 0..n {
                let v = rx.recv().await.unwrap();
                assert_eq!(v.get_id(), i + 1);
                assert_eq!(v.get_val(), i);
            }
        });

        local.await;
        h1.await.unwrap();
        h2.await.unwrap();
        drop(fifo); // ensure the Fifo lives long enough
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
        let mut fifo = Fifo::<TestValue>::new(len);
        let rx = fifo.async_receiver(s.clone());
        let mut handles = Vec::with_capacity(senders as _);
        let local = tokio::task::LocalSet::new();

        for t in 0..senders {
            let tx = fifo.async_sender(s.clone());
            handles.push(local.spawn_local(async move {
                for i in 0..n {
                    let id = t * n + i + 1;
                    tx.send(&TestValue::new(id, i)).await.unwrap();
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
        drop(fifo); // ensure the Fifo lives long enough
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

        fn notify(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output = ()> + '_>> {
            async move {
                let _ = match event {
                    QueueEvent::NotEmpty => self.not_empty.send(()),
                    QueueEvent::NotFull => self.not_full.send(()),
                };
            }.boxed()
        }
    }
}
