/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use fortanix_sgx_abi::FifoDescriptor;
use std::cell::UnsafeCell;
use std::mem;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub fn bounded<T, S>(len: usize, s: S) -> (Sender<T, S>, Receiver<T, S>)
where
    T: Identified,
    S: Synchronizer,
{
    let arc = Arc::new(Fifo::new(len));
    let inner = FifoInner::from_arc(arc);
    let tx = Sender { inner: inner.clone(), synchronizer: s.clone() };
    let rx = Receiver { inner, synchronizer: s };
    (tx, rx)
}

pub fn bounded_async<T, S>(len: usize, s: S) -> (AsyncSender<T, S>, AsyncReceiver<T, S>)
where
    T: Identified,
    S: AsyncSynchronizer,
{
    let arc = Arc::new(Fifo::new(len));
    let inner = FifoInner::from_arc(arc);
    let tx = AsyncSender { inner: inner.clone(), synchronizer: s.clone() };
    let rx = AsyncReceiver { inner, synchronizer: s };
    (tx, rx)
}

pub(crate) struct Fifo<T> {
    data: Box<[T]>,
    offsets: Box<AtomicUsize>,
}

impl<T: Identified> Fifo<T> {
    fn new(len: usize) -> Self {
        assert!(
            len.is_power_of_two(),
            "Fifo len should be a power of two"
        );
        let mut data = Vec::with_capacity(len);
        data.resize_with(len, T::empty);
        Self {
            data: data.into_boxed_slice(),
            offsets: Box::new(AtomicUsize::new(0)),
        }
    }
}

enum Storage<T> {
    Shared(Arc<Fifo<T>>),
    Static,
}

impl<T> Clone for Storage<T> {
    fn clone(&self) -> Self {
        match self {
            Storage::Shared(arc) => Storage::Shared(arc.clone()),
            Storage::Static => Storage::Static,
        }
    }
}

pub(crate) struct FifoInner<T> {
    data: NonNull<[UnsafeCell<T>]>,
    offsets: NonNull<AtomicUsize>,
    storage: Storage<T>,
}

impl<T> Clone for FifoInner<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            offsets: self.offsets.clone(),
            storage: self.storage.clone(),
        }
    }
}

impl<T: Identified> FifoInner<T> {
    pub(crate) unsafe fn from_descriptor(descriptor: FifoDescriptor<T>) -> Self {
        assert!(
            descriptor.len.is_power_of_two(),
            "Fifo len should be a power of two"
        );
        #[cfg(target_env = "sgx")] {
            // check pointers are outside enclave range, etc.
            use std::os::fortanix_sgx::usercalls::alloc::User;
            let data = User::<[T]>::from_raw_parts(descriptor.data, descriptor.len);
            mem::forget(data);
        }
        let data_slice = std::slice::from_raw_parts_mut(descriptor.data, descriptor.len);
        Self {
            data: NonNull::new_unchecked(data_slice as *mut [T] as *mut [UnsafeCell<T>]),
            offsets: NonNull::new_unchecked(descriptor.offsets as *mut AtomicUsize),
            storage: Storage::Static,
        }
    }

    fn from_arc(fifo: Arc<Fifo<T>>) -> Self {
        unsafe {
            Self {
                data: NonNull::new_unchecked(fifo.data.as_ref() as *const [T] as *mut [T] as *mut [UnsafeCell<T>]),
                offsets: NonNull::new_unchecked(fifo.offsets.as_ref() as *const AtomicUsize as *mut AtomicUsize),
                storage: Storage::Shared(fifo),
            }
        }
    }

    /// Consumes `self` and returns a DescriptorGuard.
    /// Panics if `self` was created using `from_descriptor`.
    pub(crate) fn into_descriptor_guard(self) -> DescriptorGuard<T> {
        let arc = match self.storage {
            Storage::Shared(arc) => arc,
            Storage::Static => panic!("Sender/Receiver created using `from_descriptor()` cannot be turned into DescriptorGuard."),
        };
        let data = unsafe { self.data.as_ref() };
        let descriptor = FifoDescriptor {
            data: data.as_ptr() as _,
            len: data.len(),
            offsets: self.offsets.as_ptr(),
        };
        DescriptorGuard { descriptor, _fifo: arc }
    }

    fn slot(&self, index: usize) -> &mut T {
        unsafe { &mut *self.data.as_ref()[index].get() }
    }

    fn data_len(&self) -> usize {
        unsafe { self.data.as_ref().len() }
    }

    fn offsets(&self) -> &AtomicUsize {
        unsafe { self.offsets.as_ref() }
    }

    pub(crate) fn try_send_impl(&self, val: T) -> Result</*wake up reader:*/ bool, (TrySendError, T)> {
        let (new, was_empty) = loop {
            // 1. Load the current offsets.
            let current = Offsets::new(self.offsets().load(Ordering::SeqCst), self.data_len() as u32);
            let was_empty = current.is_empty();

            // 2. If the queue is full, wait, then go to step 1.
            if current.is_full() {
                return Err((TrySendError::QueueFull, val));
            }

            // 3. Add 1 to the write offset and do an atomic compare-and-swap (CAS)
            //    with the current offsets. If the CAS was not succesful, go to step 1.
            let new = current.increment_write_offset();
            let current = current.as_usize();
            let prev = self.offsets().compare_and_swap(current, new.as_usize(), Ordering::SeqCst);
            if prev == current {
                break (new, was_empty);
            }
        };

        // 4. Write the data, then the `id`.
        let slot = self.slot(new.write_offset());
        slot.copy_except_id(&val);
        slot.set_id(val.get_id_non_atomic());

        // 5. If the queue was empty in step 1, signal the reader to wake up.
        Ok(was_empty)
    }

    pub(crate) fn try_recv_impl(&self) -> Result<(T, /*wake up writer:*/ bool), TryRecvError> {
        // 1. Load the current offsets.
        let current = Offsets::new(self.offsets().load(Ordering::SeqCst), self.data_len() as u32);

        // 2. If the queue is empty, wait, then go to step 1.
        if current.is_empty() {
            return Err(TryRecvError::QueueEmpty);
        }

        // 3. Add 1 to the read offset.
        let new = current.increment_read_offset();

        let slot = loop {
            // 4. Read the `id` at the new read offset.
            let slot = self.slot(new.read_offset());
            let id = slot.get_id();

            // 5. If `id` is `0`, go to step 4 (spin). Spinning is OK because data is
            //    expected to be written imminently.
            if id != 0 {
                break slot;
            }
        };

        // 6. Read the data, then store `0` in the `id`.
        let val = *slot;
        slot.set_id(0);

        // 7. Store the new read offset.
        let before = fetch_adjust(
            self.offsets(),
            new.read as isize - current.read as isize,
            Ordering::SeqCst,
        );

        // 8. If the queue was full before step 7, signal the writer to wake up.
        let was_full = Offsets::new(before, self.data_len() as u32).is_full();
        Ok((val, was_full))
    }
}

pub(crate) fn fetch_adjust(x: &AtomicUsize, delta: isize, ord: Ordering) -> usize {
    match delta > 0 {
        true => x.fetch_add(delta as usize, ord),
        false => x.fetch_sub(-delta as usize, ord),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Offsets {
    write: u32,
    read: u32,
    len: u32,
}

impl Offsets {
    // This implementation only works on 64-bit platforms.
    fn _assert_usize_is_eight_bytes() -> [u8; 8] {
        [0u8; mem::size_of::<usize>()]
    }

    pub(crate) fn new(offsets: usize, len: u32) -> Self {
        debug_assert!(len.is_power_of_two());
        Self {
            write: (offsets >> 32) as u32,
            read: offsets as u32,
            len,
        }
    }

    pub(crate) fn as_usize(&self) -> usize {
        ((self.write as usize) << 32) | (self.read as usize)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.read == self.write
    }

    pub(crate) fn is_full(&self) -> bool {
        self.read != self.write && self.read_offset() == self.write_offset()
    }

    pub(crate) fn read_offset(&self) -> usize {
        (self.read & (self.len - 1)) as _
    }

    pub(crate) fn write_offset(&self) -> usize {
        (self.write & (self.len - 1)) as _
    }

    pub(crate) fn increment_read_offset(&self) -> Self {
        Self {
            read: (self.read + 1) & (self.len * 2 - 1),
            ..*self
        }
    }

    pub(crate) fn increment_write_offset(&self) -> Self {
        Self {
            write: (self.write + 1) & (self.len * 2 - 1),
            ..*self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NoopSynchronizer, TestValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    fn inner<T, S>(tx: Sender<T, S>) -> FifoInner<T> {
        tx.inner
    }

    #[test]
    fn basic1() {
        let (tx, _rx) = bounded(32, NoopSynchronizer);
        let inner = inner(tx);
        assert!(inner.try_recv_impl().is_err());

        for i in 1..=7 {
            let wake = inner.try_send_impl(TestValue { id: i, val: i }).unwrap();
            assert!(if i == 1 { wake } else { !wake });
        }

        for i in 1..=7 {
            let (v, wake) = inner.try_recv_impl().unwrap();
            assert!(!wake);
            assert_eq!(v.id, i);
            assert_eq!(v.val, i);
        }
        assert!(inner.try_recv_impl().is_err());
    }

    #[test]
    fn basic2() {
        let (tx, _rx) = bounded(8, NoopSynchronizer);
        let inner = inner(tx);
        for _ in 0..3 {
            for i in 1..=8 {
                inner.try_send_impl(TestValue { id: i, val: i }).unwrap();
            }
            assert!(inner.try_send_impl(TestValue { id: 9, val: 9 }).is_err());

            for i in 1..=8 {
                let (v, wake) = inner.try_recv_impl().unwrap();
                assert!(if i == 1 { wake } else { !wake });
                assert_eq!(v.id, i);
                assert_eq!(v.val, i);
            }
            assert!(inner.try_recv_impl().is_err());
        }
    }

    #[test]
    fn multi_threaded() {
        let (tx, rx) = bounded(32, NoopSynchronizer);
        assert!(rx.try_recv().is_err());

        let (signal_tx, signal_rx) = mpsc::channel();

        let h = thread::spawn(move || {
            for _ in 0..4 {
                for i in 0..7 {
                    tx.try_send(TestValue { id: i + 1, val: i }).unwrap();
                }
                signal_tx.send(()).unwrap();
            }
        });

        for _ in 0..4 {
            signal_rx.recv().unwrap();
            for i in 0..7 {
                let v = rx.try_recv().unwrap();
                assert_eq!(v.id, i + 1);
                assert_eq!(v.val, i);
            }
        }
        assert!(rx.try_recv().is_err());
        h.join().unwrap();
    }

    #[test]
    fn fetch_adjust_correctness() {
        let x = AtomicUsize::new(0);
        fetch_adjust(&x, 5, Ordering::SeqCst);
        assert_eq!(x.load(Ordering::SeqCst), 5);
        fetch_adjust(&x, -3, Ordering::SeqCst);
        assert_eq!(x.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn offsets() {
        let mut o = Offsets::new(/*offsets:*/ 0, /*len:*/ 4);
        assert!(o.is_empty());
        assert!(!o.is_full());

        for _ in 0..10 {
            for i in 0..4 {
                o = o.increment_write_offset();
                assert!(!o.is_empty());
                if i < 3 {
                    assert!(!o.is_full());
                } else {
                    assert!(o.is_full());
                }
            }

            assert!(!o.is_empty());
            assert!(o.is_full());

            for i in 0..4 {
                o = o.increment_read_offset();
                assert!(!o.is_full());
                if i < 3 {
                    assert!(!o.is_empty());
                } else {
                    assert!(o.is_empty());
                }
            }
        }
    }
}
