/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use fortanix_sgx_abi::{FifoDescriptor, Return, Usercall};
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::mem;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

impl<T: WithAtomicId> Fifo<T> {
    /// panics if len is not a power of two.
    pub fn new(len: usize) -> Self {
        assert!(len.is_power_of_two(), "Fifo len should be a power of two");
        let mut data = Vec::with_capacity(len);
        data.resize_with(len, T::empty);
        Self {
            data: data.into_boxed_slice(),
            offsets: Box::new(AtomicUsize::new(0)),
        }
    }

    pub fn descriptor(&mut self) -> FifoDescriptor<T> {
        FifoDescriptor {
            data: self.data.as_mut().as_mut_ptr(),
            len: self.data.len(),
            offsets: self.offsets.as_ref() as _,
        }
    }

    pub fn sender<S: Synchronizer>(&mut self, synchronizer: S) -> Sender<T, S> {
        Sender::new(self.descriptor(), synchronizer)
    }

    /// Panics if there is an existing (sync or async) receiver for the same queue.
    pub fn receiver<S: Synchronizer>(&mut self, synchronizer: S) -> Receiver<T, S> {
        Receiver::new(self.descriptor(), synchronizer)
    }

    pub fn async_sender<S: AsyncSynchronizer>(&mut self, synchronizer: S) -> AsyncSender<T, S> {
        AsyncSender::new(self.descriptor(), synchronizer)
    }

    /// Panics if there is an existing (sync or async) receiver for the same queue.
    pub fn async_receiver<S: AsyncSynchronizer>(&mut self, synchronizer: S) -> AsyncReceiver<T, S> {
        AsyncReceiver::new(self.descriptor(), synchronizer)
    }
}

pub(crate) fn try_send_impl<T: WithAtomicId>(descriptor: &FifoDescriptor<T>, val: &T) -> Result</*wake up reader:*/ bool, TrySendError> {
    let (new, was_empty) = loop {
        // 1. Load the current offsets.
        let current = unsafe {
            let offsets = (*descriptor.offsets).load(Ordering::SeqCst);
            Offsets::new(offsets, descriptor.len as u32)
        };
        let was_empty = current.is_empty();

        // 2. If the queue is full, wait, then go to step 1.
        if current.is_full() {
            return Err(TrySendError::QueueFull);
        }

        // 3. Add 1 to the write offset and do an atomic compare-and-swap (CAS)
        //    with the current offsets. If the CAS was not succesful, go to step 1.
        let new = current.increment_write_offset();
        let current = current.as_usize();
        let prev = unsafe {
            (*descriptor.offsets).compare_and_swap(current, new.as_usize(), Ordering::SeqCst)
        };
        if prev == current {
            break (new, was_empty);
        }
    };

    // 4. Write the data, then the `id`.
    let slot = unsafe { &mut *descriptor.data.add(new.write_offset()) };
    slot.copy_except_id(&val);
    slot.set_id(val.get_id());

    // 5. If the queue was empty in step 1, signal the reader to wake up.
    Ok(was_empty)
}

pub(crate) fn try_recv_impl<T: WithAtomicId>(descriptor: &FifoDescriptor<T>) -> Result<(T, /*wake up writer:*/ bool), TryRecvError> {
    // 1. Load the current offsets.
    let current = unsafe {
        let offsets = (*descriptor.offsets).load(Ordering::SeqCst);
        Offsets::new(offsets, descriptor.len as u32)
    };
    let was_full = current.is_full();

    // 2. If the queue is empty, wait, then go to step 1.
    if current.is_empty() {
        return Err(TryRecvError::QueueEmpty);
    }

    // 3. Add 1 to the read offset.
    let new = current.increment_read_offset();

    let slot = loop {
        // 4. Read the `id` at the new read offset.
        let slot = unsafe { &mut *descriptor.data.add(new.read_offset()) };
        let id = slot.get_id();

        // 5. If `id` is `0`, go to step 4 (spin). Spinning is OK because data is
        //    expected to be written imminently.
        if id != 0 {
            break slot;
        }
    };

    // 6. Read the data, then store `0` in the `id`.
    let mut val = T::empty();
    val.copy_except_id(slot);
    val.set_id(slot.get_id());
    slot.set_id(0);

    // 7. Store the new read offset.
    let after = unsafe {
        fetch_adjust(
            &*descriptor.offsets,
            new.read as isize - current.read as isize,
            Ordering::SeqCst,
        )
    };

    // 8. If the queue was full in step 1, signal the writer to wake up.
    //    ... or became full during read
    let became_full = Offsets::new(after, descriptor.len as u32).is_full();
    Ok((val, was_full || became_full))
}

lazy_static! {
    pub(crate) static ref RECEIVER_TRACKER: ReceiverTracker = ReceiverTracker::new();
}

pub(crate) struct ReceiverTracker(Mutex<HashSet<usize>>);

impl ReceiverTracker {
    fn new() -> Self {
        Self(Mutex::new(HashSet::new()))
    }

    pub(crate) fn new_receiver(&self, data_ptr: usize) {
        let already_exists = {
            let mut receivers = self.0.lock().unwrap();
            !receivers.insert(data_ptr)
        };
        if already_exists {
            panic!("Multiple receivers for the same Fifo is not allowed.");
        }
    }

    pub(crate) fn drop_receiver(&self, data_ptr: usize) {
        let mut receivers = self.0.lock().unwrap();
        receivers.remove(&data_ptr);
    }
}

// Note: we cannot have an AtomicU64 id in Usercall/Return types since they
// need to be Copy due to requirements of `UserSafeSized` (see definition of
// this trait in rust/src/libstd/sys/sgx/abi/usercalls/alloc.rs). Therefore
// all the transmutes in the implementation below.
impl WithAtomicId for Usercall {
    fn empty() -> Self {
        Self {
            id: 0,
            args: (0, 0, 0, 0, 0),
        }
    }
    fn get_id(&self) -> u64 {
        let id: &AtomicU64 = unsafe { mem::transmute(&self.id) };
        id.load(Ordering::SeqCst)
    }
    fn set_id(&mut self, new_id: u64) {
        let id: &AtomicU64 = unsafe { mem::transmute(&self.id) };
        id.store(new_id, Ordering::SeqCst);
    }
    fn copy_except_id(&mut self, from: &Self) {
        let Self { id: _, args } = from;
        self.args = *args;
    }
}

impl WithAtomicId for Return {
    fn empty() -> Self {
        Self {
            id: 0,
            value: (0, 0),
        }
    }
    fn get_id(&self) -> u64 {
        let id: &AtomicU64 = unsafe { mem::transmute(&self.id) };
        id.load(Ordering::SeqCst)
    }
    fn set_id(&mut self, new_id: u64) {
        let id: &AtomicU64 = unsafe { mem::transmute(&self.id) };
        id.store(new_id, Ordering::SeqCst);
    }
    fn copy_except_id(&mut self, from: &Self) {
        let Self { id: _, value } = from;
        self.value = *value;
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
    pub(crate) fn new(offsets: usize, len: u32) -> Self {
        Self {
            write: (offsets >> 32) as u32,
            read: (offsets & ((1 << 32) - 1)) as u32,
            len,
        }
    }

    pub(crate) fn as_usize(&self) -> usize {
        ((self.write as usize) << 32) | (self.read as usize)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.read_offset() == self.write_offset() && self.read == self.write
    }

    pub(crate) fn is_full(&self) -> bool {
        self.read_offset() == self.write_offset() && self.read != self.write
    }

    pub(crate) fn read_offset(&self) -> usize {
        (self.read % self.len) as _
    }

    pub(crate) fn write_offset(&self) -> usize {
        (self.write % self.len) as _
    }

    pub(crate) fn increment_read_offset(&self) -> Self {
        Self {
            read: (self.read + 1) % (self.len * 2),
            ..*self
        }
    }

    pub(crate) fn increment_write_offset(&self) -> Self {
        Self {
            write: (self.write + 1) % (self.len * 2),
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

    #[test]
    fn basic1() {
        let mut fifo = Fifo::<TestValue>::new(32);
        let desc = fifo.descriptor();
        assert!(try_recv_impl(&desc).is_err());

        for i in 1..=7 {
            let wake = try_send_impl(&desc, &TestValue::new(i, i)).unwrap();
            assert!(if i == 1 { wake } else { !wake });
        }

        for i in 1..=7 {
            let (v, wake) = try_recv_impl(&desc).unwrap();
            assert!(!wake);
            assert_eq!(v.get_id(), i);
            assert_eq!(v.get_val(), i);
        }
        assert!(try_recv_impl(&desc).is_err());
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn basic2() {
        let mut fifo = Fifo::<TestValue>::new(8);
        let desc = fifo.descriptor();
        for _ in 0..3 {
            for i in 1..=8 {
                try_send_impl(&desc, &TestValue::new(i, i)).unwrap();
            }
            assert!(try_send_impl(&desc, &TestValue::new(9, 9)).is_err());

            for i in 1..=8 {
                let (v, wake) = try_recv_impl(&desc).unwrap();
                assert!(if i == 1 { wake } else { !wake });
                assert_eq!(v.get_id(), i);
                assert_eq!(v.get_val(), i);
            }
            assert!(try_recv_impl(&desc).is_err());
        }
        drop(fifo); // ensure the Fifo lives long enough
    }

    #[test]
    fn multi_threaded() {
        let s = NoopSynchronizer;
        let mut fifo = Fifo::<TestValue>::new(32);
        let tx = fifo.sender(s.clone());
        let rx = fifo.receiver(s.clone());
        assert!(rx.try_recv().is_err());

        let (signal_tx, signal_rx) = mpsc::channel();

        let h = thread::spawn(move || {
            for _ in 0..4 {
                for i in 0..7 {
                    tx.try_send(&TestValue::new(i + 1, i)).unwrap();
                }
                signal_tx.send(()).unwrap();
            }
        });

        for _ in 0..4 {
            signal_rx.recv().unwrap();
            for i in 0..7 {
                let v = rx.try_recv().unwrap();
                assert_eq!(v.get_id(), i + 1);
                assert_eq!(v.get_val(), i);
            }
        }
        assert!(rx.try_recv().is_err());
        h.join().unwrap();
        drop(fifo); // ensure the Fifo lives long enough
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
    #[should_panic]
    fn multiple_receivers_not_allowed() {
        let s = NoopSynchronizer;
        let mut fifo = Fifo::<TestValue>::new(4);
        let r1 = fifo.receiver(s.clone());
        let r2 = fifo.receiver(s.clone());
        drop(r1);
        drop(r2);
        drop(fifo); // ensure the Fifo lives long enough
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
