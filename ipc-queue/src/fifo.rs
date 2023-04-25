/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::mem;
#[cfg(not(target_env = "sgx"))]
use {
    std::sync::atomic::AtomicU64,
    std::sync::Arc,
};
use std::sync::atomic::{AtomicUsize, Ordering, Ordering::SeqCst};

use fortanix_sgx_abi::{FifoDescriptor, WithId};

use super::*;

// `fortanix_sgx_abi::WithId` is not `Copy` because it contains an `AtomicU64`.
// This type has the same memory layout but is `Copy` and can be marked as
// `UserSafeSized` which is needed for the `User::from_raw_parts()` below.
#[cfg(target_env = "sgx")]
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UserSafeWithId<T> {
    pub id: u64,
    pub data: T,
}

#[cfg(target_env = "sgx")]
unsafe impl<T: UserSafeSized> UserSafeSized for UserSafeWithId<T> {}

#[cfg(target_env = "sgx")]
unsafe fn _sanity_check_with_id() {
    use std::mem::size_of;
    let _: [u8; size_of::<fortanix_sgx_abi::WithId<()>>()] = [0u8; size_of::<UserSafeWithId<()>>()];
}

#[cfg(target_env = "sgx")]
#[repr(transparent)]
#[derive(Copy, Clone)]
struct WrapUsize(usize);

#[cfg(target_env = "sgx")]
unsafe impl UserSafeSized for WrapUsize{}

#[cfg(not(target_env = "sgx"))]
pub fn bounded<T, S>(len: usize, s: S) -> (Sender<T, S>, Receiver<T, S>)
where
    T: Transmittable,
    S: Synchronizer,
{
    let arc = Arc::new(FifoBuffer::new(len));
    let inner = Fifo::from_arc(arc);
    let tx = Sender { inner: inner.clone(), synchronizer: s.clone() };
    let rx = Receiver { inner, synchronizer: s };
    (tx, rx)
}

#[cfg(not(target_env = "sgx"))]
pub fn bounded_async<T, S>(len: usize, s: S) -> (AsyncSender<T, S>, AsyncReceiver<T, S>)
where
    T: Transmittable,
    S: AsyncSynchronizer,
{
    let arc = Arc::new(FifoBuffer::new(len));
    let inner = Fifo::from_arc(arc);
    let tx = AsyncSender { inner: inner.clone(), synchronizer: s.clone() };
    let rx = AsyncReceiver { inner, synchronizer: s, read_epoch: Arc::new(AtomicU64::new(0)) };
    (tx, rx)
}

#[cfg(all(test, target_env = "sgx"))]
pub(crate) fn bounded<T, S>(len: usize, s: S) -> (Sender<T, S>, Receiver<T, S>)
where
    T: Transmittable,
    S: Synchronizer,
{
    use std::ops::DerefMut;
    use std::os::fortanix_sgx::usercalls::alloc::User;

    // Allocate [WithId<T>; len] in userspace
    // WARNING: This creates dangling memory in userspace, use in tests only!
    let mut data = User::<[UserSafeWithId<T>]>::uninitialized(len);
    data.deref_mut().iter_mut().for_each(|v| v.copy_from_enclave(&UserSafeWithId::default()));

    // WARNING: This creates dangling memory in userspace, use in tests only!
    let offsets = User::<WrapUsize>::new_from_enclave(&WrapUsize(0));
    let offsets = offsets.into_raw() as *const AtomicUsize;

    let descriptor = FifoDescriptor {
        data: data.into_raw() as _,
        len,
        offsets,
    };

    let inner = unsafe { Fifo::from_descriptor(descriptor) };
    let tx = Sender { inner: inner.clone(), synchronizer: s.clone() };
    let rx = Receiver { inner, synchronizer: s };
    (tx, rx)
}

#[cfg(not(target_env = "sgx"))]
pub(crate) struct FifoBuffer<T> {
    data: Box<[WithId<T>]>,
    offsets: Box<AtomicUsize>,
}

#[cfg(not(target_env = "sgx"))]
impl<T: Transmittable> FifoBuffer<T> {
    fn new(len: usize) -> Self {
        assert!(
            len.is_power_of_two(),
            "Fifo len should be a power of two"
        );
        let mut data = Vec::with_capacity(len);
        data.resize_with(len, || WithId { id: AtomicU64::new(0), data: T::default() });
        Self {
            data: data.into_boxed_slice(),
            offsets: Box::new(AtomicUsize::new(0)),
        }
    }
}

enum Storage<T: 'static> {
    #[cfg(not(target_env = "sgx"))]
    Shared(Arc<FifoBuffer<T>>),
    Static(PhantomData<&'static T>),
}

impl<T> Clone for Storage<T> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(not(target_env = "sgx"))]
            Storage::Shared(arc) => Storage::Shared(arc.clone()),
            Storage::Static(p) => Storage::Static(*p),
        }
    }
}

pub(crate) struct Fifo<T: 'static> {
    data: &'static [UnsafeCell<WithId<T>>],
    offsets: &'static AtomicUsize,
    storage: Storage<T>,
}

impl<T> Clone for Fifo<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data,
            offsets: self.offsets,
            storage: self.storage.clone(),
        }
    }
}

impl<T> Fifo<T> {
    pub(crate) fn current_offsets(&self, ordering: Ordering) -> Offsets {
        Offsets::new(self.offsets.load(ordering), self.data.len() as u32)
    }
}

impl<T: Transmittable> Fifo<T> {
    pub(crate) unsafe fn from_descriptor(descriptor: FifoDescriptor<T>) -> Self {
        assert!(
            descriptor.len.is_power_of_two(),
            "Fifo len should be a power of two"
        );
        #[cfg(target_env = "sgx")] {
            use std::os::fortanix_sgx::usercalls::alloc::User;

            // check pointers are outside enclave range, etc.
            let data = User::<[UserSafeWithId<T>]>::from_raw_parts(descriptor.data as _, descriptor.len);
            mem::forget(data);
            UserRef::from_ptr(descriptor.offsets as *const WrapUsize);

        }
        let data_slice = std::slice::from_raw_parts(descriptor.data, descriptor.len);
        Self {
            data: &*(data_slice as *const [WithId<T>] as *const [UnsafeCell<WithId<T>>]),
            offsets: &*descriptor.offsets,
            storage: Storage::Static(PhantomData::default()),
        }
    }

    #[cfg(not(target_env = "sgx"))]
    fn from_arc(fifo: Arc<FifoBuffer<T>>) -> Self {
        unsafe {
            Self {
                data: &*(fifo.data.as_ref() as *const [WithId<T>] as *const [UnsafeCell<WithId<T>>]),
                offsets: &*(fifo.offsets.as_ref() as *const AtomicUsize),
                storage: Storage::Shared(fifo),
            }
        }
    }

    /// Consumes `self` and returns a DescriptorGuard.
    /// Panics if `self` was created using `from_descriptor`.
    #[cfg(not(target_env = "sgx"))]
    pub(crate) fn into_descriptor_guard(self) -> DescriptorGuard<T> {
        let arc = match self.storage {
            Storage::Shared(arc) => arc,
            Storage::Static(_) => panic!("Sender/Receiver created using `from_descriptor()` cannot be turned into DescriptorGuard."),
        };
        let descriptor = FifoDescriptor {
            data: self.data.as_ptr() as _,
            len: self.data.len(),
            offsets: self.offsets,
        };
        DescriptorGuard { descriptor, _fifo: arc }
    }

    pub(crate) fn try_send_impl(&self, val: Identified<T>) -> Result</*wake up reader:*/ bool, TrySendError> {
        let (new, was_empty) = loop {
            // 1. Load the current offsets.
            let current = self.current_offsets(Ordering::SeqCst);
            let was_empty = current.is_empty();

            // 2. If the queue is full, wait, then go to step 1.
            if current.is_full() {
                return Err(TrySendError::QueueFull);
            }

            // 3. Add 1 to the write offset and do an atomic compare-and-swap (CAS)
            //    with the current offsets. If the CAS was not succesful, go to step 1.
            let new = current.increment_write_offset();
            let current = current.as_usize();
            if let Ok(_) = self.offsets.compare_exchange(current, new.as_usize(), Ordering::SeqCst, Ordering::SeqCst) {
                break (new, was_empty);
            }
        };

        // 4. Write the data, then the `id`.
        unsafe {
            let slot = &mut *self.data[new.write_offset()].get();
            T::write(&mut slot.data, &val.data);
            slot.id.store(val.id, SeqCst);
        }

        // 5. If the queue was empty in step 1, signal the reader to wake up.
        Ok(was_empty)
    }

    pub(crate) fn try_recv_impl(&self) -> Result<(Identified<T>, /*wake up writer:*/ bool, /*read offset wrapped around:*/bool), TryRecvError> {
        // 1. Load the current offsets.
        let current = self.current_offsets(Ordering::SeqCst);

        // 2. If the queue is empty, wait, then go to step 1.
        if current.is_empty() {
            return Err(TryRecvError::QueueEmpty);
        }

        // 3. Add 1 to the read offset.
        let new = current.increment_read_offset();

        let (slot, id) = loop {
            // 4. Read the `id` at the new read offset.
            let slot = unsafe { &mut *self.data[new.read_offset()].get() };
            let id = slot.id.load(Ordering::SeqCst);

            // 5. If `id` is `0`, go to step 4 (spin). Spinning is OK because data is
            //    expected to be written imminently.
            if id != 0 {
                break (slot, id);
            }
        };

        // 6. Read the data, then store `0` in the `id`.
        let data = unsafe { T::read(&slot.data) };
        let val = Identified { id, data };
        slot.id.store(0, SeqCst);

        // 7. Store the new read offset, retrieving the old offsets.
        let before = fetch_adjust(
            self.offsets,
            new.read as isize - current.read as isize,
            Ordering::SeqCst,
        );

        // 8. If the queue was full before step 7, signal the writer to wake up.
        let was_full = Offsets::new(before, self.data.len() as u32).is_full();
        Ok((val, was_full, new.read_offset() == 0))
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

    pub(crate) fn read_high_bit(&self) -> bool {
        self.read & self.len == self.len
    }

    pub(crate) fn write_high_bit(&self) -> bool {
        self.write & self.len == self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NoopSynchronizer, TestValue};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    fn inner<T, S>(tx: Sender<T, S>) -> Fifo<T> {
        tx.inner
    }

    #[test]
    fn basic1() {
        let (tx, _rx) = bounded(32, NoopSynchronizer);
        let inner = inner(tx);
        assert!(inner.try_recv_impl().is_err());

        for i in 1..=7 {
            let wake = inner.try_send_impl(Identified { id: i, data: TestValue(i) }).unwrap();
            assert!(if i == 1 { wake } else { !wake });
        }

        for i in 1..=7 {
            let (v, wake, _) = inner.try_recv_impl().unwrap();
            assert!(!wake);
            assert_eq!(v.id, i);
            assert_eq!(v.data.0, i);
        }
        assert!(inner.try_recv_impl().is_err());
    }

    #[test]
    fn basic2() {
        let (tx, _rx) = bounded(8, NoopSynchronizer);
        let inner = inner(tx);
        for _ in 0..3 {
            for i in 1..=8 {
                inner.try_send_impl(Identified { id: i, data: TestValue(i) }).unwrap();
            }
            assert!(inner.try_send_impl(Identified { id: 9, data: TestValue(9) }).is_err());

            for i in 1..=8 {
                let (v, wake, _) = inner.try_recv_impl().unwrap();
                assert!(if i == 1 { wake } else { !wake });
                assert_eq!(v.id, i);
                assert_eq!(v.data.0, i);
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
                    tx.try_send(Identified { id: i + 1, data: TestValue(i) }).unwrap();
                }
                signal_tx.send(()).unwrap();
            }
        });

        for _ in 0..4 {
            signal_rx.recv().unwrap();
            for i in 0..7 {
                let v = rx.try_recv().unwrap();
                assert_eq!(v.id, i + 1);
                assert_eq!(v.data.0, i);
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
