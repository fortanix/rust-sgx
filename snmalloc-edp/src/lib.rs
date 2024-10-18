#![no_std]

include!(concat!(env!("OUT_DIR"), "/alloc-type.rs"));

#[link(name = "snmalloc-edp", kind = "static")]
extern {
    pub fn sn_global_init();
    pub fn sn_thread_init(allocator: *mut Alloc);
    pub fn sn_thread_cleanup(allocator: *mut Alloc);

    pub fn sn_rust_alloc(alignment: usize, size: usize) -> *mut u8;
    pub fn sn_rust_alloc_zeroed(alignment: usize, size: usize) -> *mut u8;
    pub fn sn_rust_dealloc(ptr: *mut u8, alignment: usize, size: usize);
    pub fn sn_rust_realloc(ptr: *mut u8, alignment: usize, old_size: usize, new_size: usize) -> *mut u8;
}
