use crate::hacks::Usercall;
use crate::provider_core::ProviderCore;
use ipc_queue::Identified;
use std::cell::RefCell;
use std::mem;
use std::os::fortanix_sgx::usercalls::alloc::{User, UserSafe};
use std::os::fortanix_sgx::usercalls::raw::UsercallNrs;

pub trait BatchDroppable: private::BatchDroppable {}
impl<T: private::BatchDroppable> BatchDroppable for T {}

/// Drop the given value at some point in the future (no rush!). This is useful
/// for freeing userspace memory when we don't particularly care about when the
/// buffer is freed. Multiple `free` usercalls are batched together and sent to
/// userspace asynchronously. It is also guaranteed that the memory is freed if
/// the current thread exits before there is a large enough batch.
///
/// This is mainly an optimization to avoid exitting the enclave for each
/// usercall. Note that even when sending usercalls asynchronously, if the
/// usercall queue is empty we still need to exit the enclave to signal the
/// userspace that the queue is not empty anymore. The batch send would send
/// multiple usercalls and notify the userspace at most once.
pub fn batch_drop<T: BatchDroppable>(t: T) {
    t.batch_drop();
}

mod private {
    use super::*;

    const BATCH_SIZE: usize = 8;

    struct BatchDropProvider {
        core: ProviderCore,
        deferred: Vec<Identified<Usercall>>,
    }

    impl BatchDropProvider {
        pub fn new() -> Self {
            Self {
                core: ProviderCore::new(None),
                deferred: Vec::with_capacity(BATCH_SIZE),
            }
        }

        fn make_progress(&self, deferred: &[Identified<Usercall>]) -> usize {
            let sent = self.core.try_send_multiple_usercalls(deferred);
            if sent == 0 {
                self.core.send_usercall(deferred[0]);
                return 1;
            }
            sent
        }

        fn maybe_send_usercall(&mut self, u: Usercall) {
            self.deferred.push(self.core.assign_id(u));
            if self.deferred.len() < BATCH_SIZE {
                return;
            }
            let sent = self.make_progress(&self.deferred);
            let mut not_sent = self.deferred.split_off(sent);
            self.deferred.clear();
            self.deferred.append(&mut not_sent);
        }

        pub fn free<T: UserSafe + ?Sized>(&mut self, buf: User<T>) {
            let ptr = buf.into_raw();
            let size = unsafe { mem::size_of_val(&mut *ptr) };
            let alignment = T::align_of();
            let ptr = ptr as *mut u8;
            let u = Usercall(UsercallNrs::free as _, ptr as _, size as _, alignment as _, 0);
            self.maybe_send_usercall(u);
        }
    }

    impl Drop for BatchDropProvider {
        fn drop(&mut self) {
            let mut sent = 0;
            while sent < self.deferred.len() {
                sent += self.make_progress(&self.deferred[sent..]);
            }
        }
    }

    std::thread_local! {
        static PROVIDER: RefCell<BatchDropProvider> = RefCell::new(BatchDropProvider::new());
    }

    pub trait BatchDroppable {
        fn batch_drop(self);
    }

    impl<T: UserSafe + ?Sized> BatchDroppable for User<T> {
        fn batch_drop(self) {
            PROVIDER.with(|p| p.borrow_mut().free(self));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::batch_drop;
    use std::os::fortanix_sgx::usercalls::alloc::User;
    use std::thread;

    #[test]
    fn basic() {
        for _ in 0..100 {
            batch_drop(User::<[u8]>::uninitialized(100));
        }
    }

    #[test]
    fn multiple_threads() {
        const THREADS: usize = 16;
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    batch_drop(User::<[u8]>::uninitialized(100));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
