/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![cfg_attr(target_env = "sgx", feature(sgx_platform))]

use std::future::Future;
#[cfg(target_env = "sgx")]
use std::os::fortanix_sgx::usercalls::alloc::UserSafeSized;
use std::pin::Pin;
use std::sync::Arc;

use fortanix_sgx_abi::FifoDescriptor;

use self::fifo::{Fifo, FifoBuffer};

mod fifo;
mod interface_sync;
mod interface_async;
#[cfg(test)]
mod test_support;

#[cfg(target_env = "sgx")]
pub trait Transmittable: UserSafeSized + Default {}

#[cfg(target_env = "sgx")]
impl<T> Transmittable for T where T: UserSafeSized + Default {}

#[cfg(not(target_env = "sgx"))]
pub trait Transmittable: Copy + Sized + Default {}

#[cfg(not(target_env = "sgx"))]
impl<T> Transmittable for T where T: Copy + Sized + Default {}

pub fn bounded<T, S>(len: usize, s: S) -> (Sender<T, S>, Receiver<T, S>)
where
    T: Transmittable,
    S: Synchronizer,
{
    self::fifo::bounded(len, s)
}

pub fn bounded_async<T, S>(len: usize, s: S) -> (AsyncSender<T, S>, AsyncReceiver<T, S>)
where
    T: Transmittable,
    S: AsyncSynchronizer,
{
    self::fifo::bounded_async(len, s)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identified<T> {
    pub id: u64,
    pub data: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueueEvent {
    NotEmpty,
    NotFull,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrySendError {
    QueueFull,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TryRecvError {
    QueueEmpty,
    Closed,
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

pub trait Synchronizer: Clone {
    /// block execution until the specified event happens.
    fn wait(&self, event: QueueEvent) -> Result<(), SynchronizationError>;

    /// notify all waiters blocked on the specified event for the same Fifo.
    fn notify(&self, event: QueueEvent);
}

pub struct Sender<T: 'static, S> {
    inner: Fifo<T>,
    synchronizer: S,
}

pub struct Receiver<T: 'static, S> {
    inner: Fifo<T>,
    synchronizer: S,
}

pub trait AsyncSynchronizer: Clone {
    /// block execution until the specified event happens.
    fn wait(&self, event: QueueEvent) -> Pin<Box<dyn Future<Output = Result<(), SynchronizationError>> + '_>>;

    /// notify all waiters blocked on the specified event for the same Fifo.
    fn notify(&self, event: QueueEvent);
}

pub struct AsyncSender<T: 'static, S> {
    inner: Fifo<T>,
    synchronizer: S,
}

pub struct AsyncReceiver<T: 'static, S> {
    inner: Fifo<T>,
    synchronizer: S,
}

/// `DescriptorGuard<T>` can produce a `FifoDescriptor<T>` that is guaranteed
/// to remain valid as long as the DescriptorGuard is not dropped.
pub struct DescriptorGuard<T> {
    descriptor: FifoDescriptor<T>,
    _fifo: Arc<FifoBuffer<T>>,
}

impl<T> DescriptorGuard<T> {
    pub fn fifo_descriptor(&self) -> FifoDescriptor<T> {
        self.descriptor
    }
}
