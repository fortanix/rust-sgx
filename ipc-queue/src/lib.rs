/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use fortanix_sgx_abi::FifoDescriptor;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;

mod fifo;
mod interface_sync;
mod interface_async;
#[cfg(test)]
mod test_support;

/// A FIFO queue implemented according to [fortanix_sgx_abi specifications].
///
/// **NOTE:** Sender and reciever types use FifoDescriptor internally which
/// does not hold a reference to the Fifo instance, therefore users of these
/// types must ensure that the Fifo instance lives at least as long as all
/// senders and receivers for that queue.
///
/// **NOTE:** sync and async sender/receiver types should not be used together.
/// i.e. either use sync senders/receivers or the async ones, but don't mix
/// sync and async. The interfaces are designed for use in SGX enclaves (sync)
/// and enclave runner (async).
///
/// [fortanix_sgx_abi specifications]: https://edp.fortanix.com/docs/api/fortanix_sgx_abi/async/struct.FifoDescriptor.html
pub struct Fifo<T> {
    data: Box<[T]>,
    offsets: Box<AtomicUsize>,
}

/// This is used as a bound on `T` in `Fifo<T>` and related types.
/// Types that implement this trait must have an `id: AtomicU64` field and use
/// `Ordering::SeqCst` in `get_id()` and `set_id()`.
pub trait WithAtomicId {
    /// Must set the `id` field to 0.
    fn empty() -> Self;
    fn get_id(&self) -> u64;
    fn set_id(&mut self, id: u64);
    /// Copy everything except the `id` field from another instance to self.
    fn copy_except_id(&mut self, from: &Self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueueEvent {
    NotEmpty,
    NotFull,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrySendError {
    QueueFull,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TryRecvError {
    QueueEmpty,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecvError {
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SynchronizationError {
    ChannelClosed,
}

pub trait Synchronizer {
    /// block execution until the specified event happens.
    fn wait(&self, event: QueueEvent) -> Result<(), SynchronizationError>;

    /// notify all waiters blocked on the specified event for the same Fifo.
    fn notify(&self, event: QueueEvent);
}

pub struct Sender<T, S> {
    descriptor: FifoDescriptor<T>,
    synchronizer: S,
}

pub struct Receiver<T, S> {
    descriptor: FifoDescriptor<T>,
    synchronizer: S,
}

pub trait AsyncSynchronizer {
    /// block execution until the specified event happens.
    fn wait(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output = Result<(), SynchronizationError>> + '_>>;

    /// notify all waiters blocked on the specified event for the same Fifo.
    fn notify(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output = ()> + '_>>;
}

pub struct AsyncSender<T, S> {
    descriptor: FifoDescriptor<T>,
    synchronizer: S,
}

pub struct AsyncReceiver<T, S> {
    descriptor: FifoDescriptor<T>,
    synchronizer: S,
}
