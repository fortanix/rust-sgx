use super::slab::{BufSlab, Slab, SlabAllocator, User, MAX_COUNT};
use std::cmp;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;

pub const MIN_BUF_SIZE: usize = 1 << 5; // 32 bytes
pub const MAX_BUF_SIZE: usize = 1 << 16; // 64 KB
pub const NUM_SIZES: usize = 1 + (MAX_BUF_SIZE / MIN_BUF_SIZE).trailing_zeros() as usize;

pub struct SharedAllocator {
    by_size: Vec<Vec<BufSlab>>,
    byte_buffers: Vec<Slab<ByteBuffer>>,
}

unsafe impl Send for SharedAllocator {}
unsafe impl Sync for SharedAllocator {}

impl SharedAllocator {
    pub fn new(buf_counts: [usize; NUM_SIZES], byte_buffer_count: usize) -> Self {
        let mut by_size = Vec::with_capacity(NUM_SIZES);
        for i in 0..NUM_SIZES {
            by_size.push(make_buf_slabs(buf_counts[i], MIN_BUF_SIZE << i));
        }
        let byte_buffers = make_byte_buffers(byte_buffer_count);
        Self { by_size, byte_buffers }
    }

    pub fn alloc_buf(&self, size: usize) -> Option<User<[u8]>> {
        assert!(size > 0);
        if size > MAX_BUF_SIZE {
            return None;
        }
        let (_, index) = size_index(size);
        self.by_size[index].alloc()
    }

    pub fn alloc_byte_buffer(&self) -> Option<User<ByteBuffer>> {
        self.byte_buffers.alloc()
    }
}

pub struct LocalAllocator {
    initial_buf_counts: [usize; NUM_SIZES],
    initial_byte_buffer_count: usize,
    inner: SharedAllocator,
}

impl LocalAllocator {
    pub fn new(initial_buf_counts: [usize; NUM_SIZES], initial_byte_buffer_count: usize) -> Self {
        let mut by_size = Vec::with_capacity(NUM_SIZES);
        by_size.resize_with(NUM_SIZES, Default::default);
        let byte_buffers = Vec::new();
        Self {
            initial_buf_counts,
            initial_byte_buffer_count,
            inner: SharedAllocator { by_size, byte_buffers },
        }
    }

    pub fn alloc_buf(&mut self, request_size: usize) -> User<[u8]> {
        assert!(request_size > 0);
        if request_size > MAX_BUF_SIZE {
            // Always allocate very large buffers directly
            return User::<[u8]>::uninitialized(request_size);
        }
        let (size, index) = size_index(request_size);
        if let Some(buf) = self.inner.by_size[index].alloc() {
            return buf;
        }
        let slabs = &mut self.inner.by_size[index];
        if slabs.len() >= 8 {
            // Keep the number of slabs for each size small.
            return User::<[u8]>::uninitialized(request_size);
        }
        let count = slabs.last().map_or(self.initial_buf_counts[index], |s| s.count() * 2);
        // Limit each slab's count for better worst-case performance.
        let count = cmp::min(count, MAX_COUNT / 8);
        slabs.push(BufSlab::new(count, size));
        slabs.last().unwrap().alloc().expect("fresh slab failed to allocate")
    }

    pub fn alloc_byte_buffer(&mut self) -> User<ByteBuffer> {
        let bbs = &mut self.inner.byte_buffers;
        if let Some(byte_buffer) = bbs.alloc() {
            return byte_buffer;
        }
        if bbs.len() >= 8 {
            // Keep the number of slabs small.
            return User::<ByteBuffer>::uninitialized();
        }
        let count = bbs.last().map_or(self.initial_byte_buffer_count, |s| s.count() * 2);
        // Limit each slab's count for better worst-case performance.
        let count = cmp::min(count, MAX_COUNT / 8);
        bbs.push(Slab::new(count));
        bbs.last().unwrap().alloc().expect("fresh slab failed to allocate")
    }
}

fn make_buf_slabs(count: usize, size: usize) -> Vec<BufSlab> {
    match count {
        0 => Vec::new(),
        n if n < 1024 => vec![BufSlab::new(n, size)],
        n if n < 4 * 1024 => vec![BufSlab::new(n / 2, size), BufSlab::new(n / 2, size)],
        n if n < 32 * 1024 => vec![
            BufSlab::new(n / 4, size),
            BufSlab::new(n / 4, size),
            BufSlab::new(n / 4, size),
            BufSlab::new(n / 4, size),
        ],
        n => vec![
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
            BufSlab::new(n / 8, size),
        ],
    }
}

fn make_byte_buffers(count: usize) -> Vec<Slab<ByteBuffer>> {
    match count {
        0 => Vec::new(),
        n if n < 1024 => vec![Slab::new(n)],
        n if n < 4 * 1024 => vec![Slab::new(n / 2), Slab::new(n / 2)],
        n if n < 32 * 1024 => vec![Slab::new(n / 4), Slab::new(n / 4), Slab::new(n / 4), Slab::new(n / 4)],
        n => vec![
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
            Slab::new(n / 8),
        ],
    }
}

fn size_index(request_size: usize) -> (usize, usize) {
    let size = cmp::max(MIN_BUF_SIZE, request_size.next_power_of_two());
    let index = (size / MIN_BUF_SIZE).trailing_zeros() as usize;
    (size, index)
}
