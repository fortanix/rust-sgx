//! This module integrates a `Heap` into our Rust runtime as the actual
//! system allocator.  This will only be built if the
//! `use-as-rust-allocator` feature is enabled at compile time.

use core::cmp::min;
use core::ptr;
use spin::Mutex;

use heap::*;

/// Either our global system heap, or `None` if it hasn't been allocated
/// yet.
static HEAP: Mutex<Option<Heap<'static>>> = Mutex::new(None);

pub unsafe fn initialize_allocator(
    heap_base: *mut u8,
    heap_size: usize,
    free_lists: &'static mut [*mut FreeBlock])
{
    let mut heap = HEAP.lock();
    *heap = Some(Heap::new(heap_base, heap_size, free_lists));
}

#[no_mangle]
pub extern "C" fn __rust_allocate(size: usize, align: usize) -> *mut u8 {
    unsafe {
        HEAP.lock().as_mut()
            .expect("Must call initialize_allocator before allocating on heap")
            .allocate(size, align)
    }
}

#[no_mangle]
pub extern "C" fn __rust_deallocate(ptr: *mut u8, old_size: usize, align: usize) {
    unsafe {
        HEAP.lock().as_mut()
            .expect("Trying to deallocate before heap is initialized")
            .deallocate(ptr, old_size, align)
    }
}

/// Attempt to resize an existing block of memory, preserving as much data
/// as possible.  For now, we always just allocate new memory, copy data,
/// and deallocate the old memory.
#[no_mangle]
pub extern "C" fn __rust_reallocate(
    ptr: *mut u8, old_size: usize, size: usize, align: usize)
    -> *mut u8
{
    let new_ptr = __rust_allocate(size, align);
    if new_ptr.is_null() {
        return new_ptr;
    } else {
        unsafe { ptr::copy(ptr, new_ptr, min(size, old_size)); }
        __rust_deallocate(ptr, old_size, align);
        new_ptr
    }
}

/// We do not support in-place reallocation, so just return `old_size`.
#[no_mangle]
pub extern "C" fn __rust_reallocate_inplace(
    _ptr: *mut u8, old_size: usize, _size: usize, _align: usize)
    -> usize
{
    old_size
}

/// I have no idea what this actually does, but we're supposed to have one,
/// and the other backends to implement it as something equivalent to the
/// following.
#[no_mangle]
pub extern "C" fn __rust_usable_size(size: usize, _align: usize) -> usize {
    size
}
