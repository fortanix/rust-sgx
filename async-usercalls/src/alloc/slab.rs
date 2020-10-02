use super::bitmap::OptionalBitmap;
use std::cell::UnsafeCell;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::fortanix_sgx::usercalls::alloc::{User as StdUser, UserRef, UserSafe, UserSafeSized};
use std::sync::Arc;

pub const MIN_COUNT: usize = 8;
pub const MAX_COUNT: usize = 64 * 1024;
pub const MIN_UNIT_LEN: usize = 32;

pub trait SlabAllocator {
    type Output;

    fn alloc(&self) -> Option<Self::Output>;
    fn count(&self) -> usize;
    fn total_size(&self) -> usize;
}

impl<A: SlabAllocator> SlabAllocator for Vec<A> {
    type Output = A::Output;

    fn alloc(&self) -> Option<Self::Output> {
        for a in self.iter() {
            if let Some(buf) = a.alloc() {
                return Some(buf);
            }
        }
        None
    }

    fn count(&self) -> usize {
        self.iter().map(|a| a.count()).sum()
    }

    fn total_size(&self) -> usize {
        self.iter().map(|a| a.total_size()).sum()
    }
}

struct Storage<T: UserSafeSized> {
    user: UnsafeCell<StdUser<[T]>>,
    bitmap: OptionalBitmap,
}

pub struct BufSlab {
    storage: Arc<Storage<u8>>,
    unit_len: usize,
}

impl BufSlab {
    pub fn new(count: usize, unit_len: usize) -> Self {
        assert!(count.is_power_of_two() && count >= MIN_COUNT && count <= MAX_COUNT);
        assert!(unit_len.is_power_of_two() && unit_len >= MIN_UNIT_LEN);
        BufSlab {
            storage: Arc::new(Storage {
                user: UnsafeCell::new(StdUser::<[u8]>::uninitialized(count * unit_len)),
                bitmap: OptionalBitmap::new(count),
            }),
            unit_len,
        }
    }
}

impl SlabAllocator for BufSlab {
    type Output = User<[u8]>;

    fn alloc(&self) -> Option<Self::Output> {
        let index = self.storage.bitmap.reserve()?;
        let start = index * self.unit_len;
        let end = start + self.unit_len;
        let user = unsafe { &mut *self.storage.user.get() };
        let user_ref = &mut user[start..end];
        Some(User {
            user_ref,
            storage: self.storage.clone(),
            index,
        })
    }

    fn count(&self) -> usize {
        self.total_size() / self.unit_len
    }

    fn total_size(&self) -> usize {
        let user = unsafe { &*self.storage.user.get() };
        user.len()
    }
}

pub trait UserSafeExt: UserSafe {
    type Element: UserSafeSized;
}

impl<T: UserSafeSized> UserSafeExt for [T] {
    type Element = T;
}

impl<T: UserSafeSized> UserSafeExt for T {
    type Element = T;
}

pub struct User<T: UserSafeExt + ?Sized + 'static> {
    user_ref: &'static mut UserRef<T>,
    storage: Arc<Storage<T::Element>>,
    index: usize,
}

unsafe impl<T: UserSafeExt + ?Sized + Send> Send for User<T> {}

impl<T: UserSafeSized> User<T> {
    pub fn uninitialized() -> Self {
        let storage = Arc::new(Storage {
            user: UnsafeCell::new(StdUser::<[T]>::uninitialized(1)),
            bitmap: OptionalBitmap::none(),
        });
        let user = unsafe { &mut *storage.user.get() };
        let user_ref = &mut user[0];
        Self {
            user_ref,
            storage,
            index: 0,
        }
    }
}

impl<T: UserSafeSized> User<[T]> {
    pub fn uninitialized(n: usize) -> Self {
        let storage = Arc::new(Storage {
            user: UnsafeCell::new(StdUser::<[T]>::uninitialized(n)),
            bitmap: OptionalBitmap::none(),
        });
        let user = unsafe { &mut *storage.user.get() };
        let user_ref = &mut user[..];
        Self {
            user_ref,
            storage,
            index: 0,
        }
    }
}

impl<T: UserSafeExt + ?Sized> Drop for User<T> {
    fn drop(&mut self) {
        self.storage.bitmap.unset(self.index);
    }
}

impl<T: UserSafeExt + ?Sized> Deref for User<T> {
    type Target = UserRef<T>;

    fn deref(&self) -> &Self::Target {
        self.user_ref
    }
}

impl<T: UserSafeExt + ?Sized> DerefMut for User<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.user_ref
    }
}

pub struct Slab<T: UserSafeSized>(Arc<Storage<T>>);

impl<T: UserSafeSized> Slab<T> {
    pub fn new(count: usize) -> Self {
        assert!(count.is_power_of_two() && count >= MIN_COUNT && count <= MAX_COUNT);
        Slab(Arc::new(Storage {
            user: UnsafeCell::new(StdUser::<[T]>::uninitialized(count)),
            bitmap: OptionalBitmap::new(count),
        }))
    }
}

impl<T: UserSafeSized + 'static> SlabAllocator for Slab<T> {
    type Output = User<T>;

    fn alloc(&self) -> Option<Self::Output> {
        let index = self.0.bitmap.reserve()?;
        let user = unsafe { &mut *self.0.user.get() };
        let user_ref = &mut user[index];
        Some(User {
            user_ref,
            storage: self.0.clone(),
            index,
        })
    }

    fn count(&self) -> usize {
        let user = unsafe { &*self.0.user.get() };
        user.len()
    }

    fn total_size(&self) -> usize {
        let user = unsafe { &*self.0.user.get() };
        user.len() * mem::size_of::<T>()
    }
}
