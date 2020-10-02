use super::allocator::SharedAllocator;
use super::bitmap::*;
use super::io_bufs::{ReadBuffer, UserBuf, WriteBuffer};
use super::slab::{BufSlab, Slab, SlabAllocator, User};
use crossbeam_channel as mpmc;
use std::collections::HashSet;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;
use std::sync::atomic::*;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

// Copied from Rust tests (test/ui/mpsc_stress.rs)
struct Barrier {
    // Not using mutex/condvar for precision
    shared: Arc<AtomicUsize>,
    count: usize,
}

impl Barrier {
    fn new(count: usize) -> Vec<Barrier> {
        let shared = Arc::new(AtomicUsize::new(0));
        (0..count)
            .map(|_| Barrier {
                shared: shared.clone(),
                count: count,
            })
            .collect()
    }

    /// Returns when `count` threads enter `wait`
    fn wait(self) {
        self.shared.fetch_add(1, Ordering::SeqCst);
        while self.shared.load(Ordering::SeqCst) != self.count {}
    }
}

#[test]
fn bitmap() {
    const BITS: usize = 1024;
    let bitmap = OptionalBitmap::new(BITS);
    for _ in 0..BITS {
        assert!(bitmap.reserve().is_some());
    }
    let mut indices = vec![34, 7, 5, 6, 120, 121, 122, 127, 0, 9]
        .into_iter()
        .collect::<HashSet<_>>();
    for &i in indices.iter() {
        bitmap.unset(i);
    }
    while let Some(index) = bitmap.reserve() {
        assert!(indices.remove(&index));
    }
    assert!(indices.is_empty());
}

#[test]
fn bitmap_concurrent_use() {
    const BITS: usize = 16;
    const THREADS: usize = 4;
    let bitmap = Arc::new(OptionalBitmap::new(BITS));
    for _ in 0..BITS - THREADS {
        bitmap.reserve().unwrap();
    }
    let mut handles = Vec::with_capacity(THREADS);
    let mut barriers = Barrier::new(THREADS);
    let (tx, rx) = mpmc::unbounded();

    for _ in 0..THREADS {
        let bitmap = Arc::clone(&bitmap);
        let barrier = barriers.pop().unwrap();
        let tx = tx.clone();

        handles.push(thread::spawn(move || {
            barrier.wait();
            let index = bitmap.reserve().unwrap();
            tx.send(index).unwrap();
        }));
    }
    drop(tx);
    for x in rx.iter() {
        bitmap.unset(x);
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn buf_slab() {
    const COUNT: usize = 16;
    const SIZE: usize = 64;
    let buf_slab = BufSlab::new(COUNT, SIZE);

    let bufs = (0..COUNT)
        .map(|_| {
            let buf = buf_slab.alloc().unwrap();
            assert!(buf.len() == SIZE);
            buf
        })
        .collect::<Vec<_>>();

    assert!(buf_slab.alloc().is_none());
    drop(bufs);
    assert!(buf_slab.alloc().is_some());
}

#[test]
fn byte_buffer_slab() {
    const COUNT: usize = 256;
    let slab = Slab::<ByteBuffer>::new(COUNT);

    let bufs = (0..COUNT)
        .map(|_| slab.alloc().unwrap())
        .collect::<Vec<User<ByteBuffer>>>();

    assert!(slab.alloc().is_none());
    drop(bufs);
    assert!(slab.alloc().is_some());
}

#[test]
fn user_is_send() {
    const COUNT: usize = 16;
    const SIZE: usize = 1024;
    let buf_slab = BufSlab::new(COUNT, SIZE);

    let mut user = buf_slab.alloc().unwrap();

    let h = thread::spawn(move || {
        user[0..5].copy_from_enclave(b"hello");
    });

    h.join().unwrap();
}

fn slab_speed(count: usize) {
    let t0 = Instant::now();
    const SIZE: usize = 32;
    const N: u32 = 100_000;
    let buf_slab = BufSlab::new(count, SIZE);

    let bufs = (0..count - 1).map(|_| buf_slab.alloc().unwrap()).collect::<Vec<_>>();

    let mut x = 0;
    for _ in 0..N {
        let b = buf_slab.alloc().unwrap();
        x += b.len();
    }
    drop(bufs);
    drop(buf_slab);
    let d = t0.elapsed();
    assert!(x > 0); // prevent the compiler from removing the whole loop above in release mode
    println!("count = {} took {:?}", count, d / N);
}

#[test]
#[ignore]
fn speed_slab() {
    println!("\n");
    for i in 3..=16 {
        slab_speed(1 << i);
    }
}

#[test]
#[ignore]
fn speed_direct() {
    use std::os::fortanix_sgx::usercalls::alloc::User;

    let t0 = Instant::now();
    const SIZE: usize = 32;
    const N: u32 = 100_000;
    let mut x = 0;
    for _ in 0..N {
        let b = User::<[u8]>::uninitialized(SIZE);
        x += b.len();
    }
    let d = t0.elapsed();
    assert!(x > 0);
    println!("took {:?}", d / N);
}

#[test]
fn shared_allocator() {
    let a = SharedAllocator::new(
        [
            /*32:*/ 2048, /*64:*/ 1024, /*128:*/ 512, /*256:*/ 256, /*512:*/ 128,
            /*1K:*/ 64, /*2K:*/ 0, /*4K:*/ 0, /*8K:*/ 0, /*16K:*/ 0, /*32K:*/ 0,
            /*64K:*/ 1024,
        ],
        1024,
    );
    for size in 1..=32 {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 32);
    }
    for size in 33..=64 {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 64);
    }
    for &size in &[65, 79, 83, 120, 127, 128] {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 128);
    }
    for &size in &[129, 199, 210, 250, 255, 256] {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 256);
    }
    for &size in &[257, 299, 365, 500, 512] {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 512);
    }
    for &size in &[513, 768, 1023, 1024] {
        let b = a.alloc_buf(size).unwrap();
        assert!(b.len() == 1024);
    }
    for i in 2..=32 {
        assert!(a.alloc_buf(i * 1024).is_none());
    }
    for i in 33..=64 {
        let b = a.alloc_buf(i * 1024).unwrap();
        assert!(b.len() == 64 * 1024);
    }
}

fn alloc_speed(count: usize) {
    let t0 = Instant::now();
    const SIZE: usize = 32;
    const N: u32 = 100_000;

    let bufs = (0..count - 1).map(|_| super::alloc_buf(SIZE)).collect::<Vec<_>>();

    let mut x = 0;
    for _ in 0..N {
        let b = super::alloc_buf(SIZE);
        x += b.len();
    }
    drop(bufs);
    let d = t0.elapsed();
    assert!(x > 0);
    println!("count = {} took {:?}", count, d / N);
}

#[test]
#[ignore]
fn speed_overall() {
    println!("\n");
    for i in 3..=14 {
        alloc_speed(1 << i);
    }
}

#[test]
fn alloc_buf_size() {
    let b = super::alloc_buf(32);
    assert_eq!(b.len(), 32);
    let b = super::alloc_buf(128);
    assert_eq!(b.len(), 128);
    let b = super::alloc_buf(900);
    assert_eq!(b.len(), 1024);
    let b = super::alloc_buf(8 * 1024);
    assert_eq!(b.len(), 8 * 1024);
}

#[test]
fn write_buffer_basic() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let chunk = write_buffer.consumable_chunk().unwrap();
    write_buffer.consume(chunk, 200);
    assert_eq!(write_buffer.write(&buf), 200);
    assert_eq!(write_buffer.write(&buf), 0);
}

#[test]
#[should_panic]
fn call_consumable_chunk_twice() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let chunk1 = write_buffer.consumable_chunk().unwrap();
    let _ = write_buffer.consumable_chunk().unwrap();
    drop(chunk1);
}

#[test]
#[should_panic]
fn consume_wrong_buf() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let unrelated_buf: UserBuf = super::alloc_buf(512).into();
    write_buffer.consume(unrelated_buf, 100);
}

#[test]
fn read_buffer_basic() {
    let mut buf = super::alloc_buf(64);
    const DATA: &'static [u8] = b"hello";
    buf[0..DATA.len()].copy_from_enclave(DATA);

    let mut read_buffer = ReadBuffer::new(buf, DATA.len());
    assert_eq!(read_buffer.len(), DATA.len());
    assert_eq!(read_buffer.remaining_bytes(), DATA.len());
    let mut buf = [0u8; 8];
    assert_eq!(read_buffer.read(&mut buf), DATA.len());
    assert_eq!(read_buffer.remaining_bytes(), 0);
    assert_eq!(&buf, b"hello\0\0\0");
}
