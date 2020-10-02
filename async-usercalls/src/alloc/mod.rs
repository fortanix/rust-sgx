use std::cell::RefCell;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;

mod allocator;
mod bitmap;
mod io_bufs;
mod slab;
#[cfg(test)]
mod tests;

use self::allocator::{LocalAllocator, SharedAllocator};
pub use self::io_bufs::{ReadBuffer, UserBuf, WriteBuffer};
pub use self::slab::{User, UserSafeExt};

/// Allocates a slice of bytes in userspace that is at least as large as `size`.
pub fn alloc_buf(size: usize) -> User<[u8]> {
    if let Some(buf) = SHARED.alloc_buf(size) {
        return buf;
    }
    LOCAL.with(|local| local.borrow_mut().alloc_buf(size))
}

/// Allocates a `ByteBuffer` in userspace.
pub fn alloc_byte_buffer() -> User<ByteBuffer> {
    if let Some(bb) = SHARED.alloc_byte_buffer() {
        return bb;
    }
    LOCAL.with(|local| local.borrow_mut().alloc_byte_buffer())
}

lazy_static::lazy_static! {
    static ref SHARED: SharedAllocator = SharedAllocator::new(
        [
            8192, // x 32 bytes
            4096, // x 64 bytes
            2048, // x 128 bytes
            1024, // x 256 bytes
            512,  // x 512 bytes
            256,  // x 1 KB
            64,   // x 2 KB
            32,   // x 4 KB
            16,   // x 8 KB
            1024, // x 16 KB
            32,   // x 32 KB
            16,   // x 64 KB
        ],
        8192, // x ByteBuffer(s)
    );
}

std::thread_local! {
    static LOCAL: RefCell<LocalAllocator> = RefCell::new(LocalAllocator::new(
        [
            128, // x 32 bytes
            64,  // x 64 bytes
            32,  // x 128 bytes
            16,  // x 256 bytes
            8,   // x 512 bytes
            8,   // x 1 KB
            8,   // x 2 KB
            8,   // x 4 KB
            8,   // x 8 KB
            8,   // x 16 KB
            8,   // x 32 KB
            8,   // x 64 KB
        ],
        64, // x ByteBuffer(s)
    ));
}
