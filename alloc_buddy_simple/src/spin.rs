// From spin v0.4.5
// 
// Copyright (c) 2014 Mathijs van de Nes
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use core::sync::atomic::{AtomicBool, Ordering, ATOMIC_BOOL_INIT};
use core::cell::UnsafeCell;
use core::marker::Sync;
use core::ops::{Drop, Deref, DerefMut};
use core::fmt;
use core::option::Option::{self, None, Some};
use core::default::Default;

/// Called while spinning (name borrowed from Linux). Can be implemented to call
/// a platform-specific method of lightening CPU load in spinlocks.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub fn cpu_relax() {
    // This instruction is meant for usage in spinlock loops
    // (see Intel x86 manual, III, 4.2)
    unsafe { asm!("pause" :::: "volatile"); }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[inline(always)]
pub fn cpu_relax() {
}

/// This type provides MUTual EXclusion based on spinning.
///
/// # Description
///
/// This structure behaves a lot like a normal Mutex. There are some differences:
///
/// - It may be used outside the runtime.
///   - A normal mutex will fail when used without the runtime, this will just lock
///   - When the runtime is present, it will call the deschedule function when appropriate
/// - No lock poisoning. When a fail occurs when the lock is held, no guarantees are made
///
/// When calling rust functions from bare threads, such as C `pthread`s, this lock will be very
/// helpful. In other cases however, you are encouraged to use the locks from the standard
/// library.
///
/// # Simple examples
///
/// ```
/// use spin;
/// let spin_mutex = spin::Mutex::new(0);
///
/// // Modify the data
/// {
///     let mut data = spin_mutex.lock();
///     *data = 2;
/// }
///
/// // Read the data
/// let answer =
/// {
///     let data = spin_mutex.lock();
///     *data
/// };
///
/// assert_eq!(answer, 2);
/// ```
///
/// # Thread-safety example
///
/// ```
/// use spin;
/// use std::sync::{Arc, Barrier};
///
/// let numthreads = 1000;
/// let spin_mutex = Arc::new(spin::Mutex::new(0));
///
/// // We use a barrier to ensure the readout happens after all writing
/// let barrier = Arc::new(Barrier::new(numthreads + 1));
///
/// for _ in (0..numthreads)
/// {
///     let my_barrier = barrier.clone();
///     let my_lock = spin_mutex.clone();
///     std::thread::spawn(move||
///     {
///         let mut guard = my_lock.lock();
///         *guard += 1;
///
///         // Release the lock to prevent a deadlock
///         drop(guard);
///         my_barrier.wait();
///     });
/// }
///
/// barrier.wait();
///
/// let answer = { *spin_mutex.lock() };
/// assert_eq!(answer, numthreads);
/// ```
pub struct Mutex<T: ?Sized>
{
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

/// A guard to which the protected data can be accessed
///
/// When the guard falls out of scope it will release the lock.
pub struct MutexGuard<'a, T: ?Sized + 'a>
{
    lock: &'a AtomicBool,
    data: &'a mut T,
}

// Same unsafe impls as `std::sync::Mutex`
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T>
{
    /// Creates a new spinlock wrapping the supplied data.
    ///
    /// May be used statically:
    ///
    /// ```
    /// use spin;
    ///
    /// static MUTEX: spin::Mutex<()> = spin::Mutex::new(());
    ///
    /// fn demo() {
    ///     let lock = MUTEX.lock();
    ///     // do something with lock
    ///     drop(lock);
    /// }
    /// ```
    pub const fn new(user_data: T) -> Mutex<T>
    {
        Mutex
        {
            lock: ATOMIC_BOOL_INIT,
            data: UnsafeCell::new(user_data),
        }
    }
}

impl<T: ?Sized> Mutex<T>
{
    fn obtain_lock(&self)
    {
        while self.lock.compare_and_swap(false, true, Ordering::Acquire) != false
        {
            // Wait until the lock looks unlocked before retrying
            while self.lock.load(Ordering::Relaxed)
            {
                cpu_relax();
            }
        }
    }

    /// Locks the spinlock and returns a guard.
    ///
    /// The returned value may be dereferenced for data access
    /// and the lock will be dropped when the guard falls out of scope.
    ///
    /// ```
    /// let mylock = spin::Mutex::new(0);
    /// {
    ///     let mut data = mylock.lock();
    ///     // The lock is now locked and the data can be accessed
    ///     *data += 1;
    ///     // The lock is implicitly dropped
    /// }
    ///
    /// ```
    pub fn lock(&self) -> MutexGuard<T>
    {
        self.obtain_lock();
        MutexGuard
        {
            lock: &self.lock,
            data: unsafe { &mut *self.data.get() },
        }
    }

    /// Tries to lock the mutex. If it is already locked, it will return None. Otherwise it returns
    /// a guard within Some.
    pub fn try_lock(&self) -> Option<MutexGuard<T>>
    {
        if self.lock.compare_and_swap(false, true, Ordering::Acquire) == false
        {
            Some(
                MutexGuard {
                    lock: &self.lock,
                    data: unsafe { &mut *self.data.get() },
                }
            )
        }
        else
        {
            None
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self.try_lock()
        {
            Some(guard) => write!(f, "Mutex {{ data: {:?} }}", &*guard),
            None => write!(f, "Mutex {{ <locked> }}"),
        }
    }
}

impl<T: ?Sized + Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(Default::default())
    }
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T>
{
    type Target = T;
    fn deref<'b>(&'b self) -> &'b T { &*self.data }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T>
{
    fn deref_mut<'b>(&'b mut self) -> &'b mut T { &mut *self.data }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T>
{
    /// The dropping of the MutexGuard will release the lock it was created from.
    fn drop(&mut self)
    {
        self.lock.store(false, Ordering::Release);
    }
}
