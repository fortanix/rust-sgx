#![no_std]

use core::ffi::c_void;

#[repr(C)]
pub struct Alloc {
    _data: [u8; 0],
    _marker:
        core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[link(name = "snmalloc-edp", kind = "static")]
extern {
    pub fn sn_global_init(heap_start_address: *mut c_void, heap_end_address: *mut c_void);
    pub fn sn_thread_init(allocator: *mut Alloc);
    pub fn sn_thread_cleanup(allocator: *mut Alloc);
    pub static sn_alloc_size: usize;
    pub static sn_alloc_align: usize;

    pub fn sn_rust_alloc(alignment: usize, size: usize) -> *mut u8;
    pub fn sn_rust_alloc_zeroed(alignment: usize, size: usize) -> *mut u8;
    pub fn sn_rust_dealloc(ptr: *mut u8, alignment: usize, size: usize);
    pub fn sn_rust_realloc(ptr: *mut u8, alignment: usize, old_size: usize, new_size: usize) -> *mut u8;
}
