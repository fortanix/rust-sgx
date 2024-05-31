/* This test based on the following pseudo code and tests correctness of our
 * new allocator snmalloc

   for 0..num_threads {
    loop {
        let mut regions: Vec<(Box<[u8], u8>)>;
        let mut mem_used = 0u64;
        match rnd % 4 {
           0 => // Check area
           1..2 => // Alloc random area if less than x% of the heap is used (not 100% to
                   // account for fragmentation, ...) and check area.
           3 => // Free random area
        }
    }
}
 * So this basically runs for a long time and should never crash.
 * The todos before running this test is there in the description of
 * https://fortanix.atlassian.net/browse/RTE-39 (under the heading
 * "Instructions on how to run the test:" )
 */

use core::arch::asm;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;
use std::sync::{Arc};
use std::thread;

#[cfg(target_env = "sgx")]
extern "C" {
    static HEAP_BASE: u64;
    static HEAP_SIZE: usize;
}

const PAGE_SIZE: usize = 4096;
const TO_KB: usize = 1024;
const TO_MB: usize = TO_KB * 1024;
const TO_GB: usize = TO_MB * 1024;
const ALIGN: usize = PAGE_SIZE;

const NUM_OPERATION_CHOICES: usize = 4;
static HEAP_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

/* Set of configurable parameters. These will adjusted as necessary while
 * recording the performance numbers. Since this test will be in CI, I have
 * kept the parameters to be less memory intensive.
 */
const NUM_THREADS: usize = 100;
/* PER_THREAD_PER_BUFFER_MAX_SIZE is max size of a buffer that a thread can allocate
 * on each call to add_new_buffer() function. Higher the value, more will be
 * the total memory consumption and more time taken by the test.
 */
const PER_THREAD_PER_BUFFER_MAX_SIZE: usize = 18 * TO_MB;
/* MAX_BUFFER_CHECKS_PER_THREAD_ITERATION is the maximum number of buffers to
 * check on each call to select_and_check_random_buffer_contents()
 */
const MAX_BUFFER_CHECKS_PER_THREAD_ITERATION: usize = 4;
/* MAX_INDEX_CHECKS_PER_BUFFER is the number of indices/locations to check
 * per buffer.
 */
const MIN_ALLOWED_FREE_HEAP_PERCENTAGE: f64 = 10.0;
/* MAX_ITERATIONS_PER_THREAD is the number of operations per thread (1 operation per
 * per iteration)
 */
const MAX_ITERATIONS_PER_THREAD: usize = 4;

#[cfg(target_env = "sgx")]
#[inline(always)]
pub fn image_base() -> u64 {
    let base: u64;
    unsafe {
        asm!(
            "lea IMAGE_BASE(%rip), {}",
            lateout(reg) base,
            options(att_syntax, nostack, preserves_flags, nomem, pure),
        )
    };
    base
}

#[cfg(target_env = "sgx")]
#[inline(always)]
pub(crate) unsafe fn rel_ptr_mut<T>(offset: u64) -> *mut T {
    (image_base() + offset) as *mut T
}

/* Returns the base memory address of the heap */
#[cfg(target_env = "sgx")]
pub(crate) fn heap_base() -> *const u8 {
    unsafe { rel_ptr_mut(HEAP_BASE) }

}

/* Returns the size of the heap */
pub(crate) fn heap_size() -> usize {
    #[cfg(target_env = "sgx")]
    unsafe { HEAP_SIZE }
    #[cfg(not(target_env = "sgx"))]
    usize::MAX
}

fn update_occupied_heap_size_on_delete(size: usize) {
    HEAP_ALLOCATED.fetch_sub(size, Ordering::SeqCst);
}

fn update_occupied_heap_size_on_addition(size: usize) {
    HEAP_ALLOCATED.fetch_add(size, Ordering::SeqCst);
}

fn get_occupied_heap_size() -> usize {
    HEAP_ALLOCATED.load(Ordering::SeqCst)
}

fn get_free_heap_size_in_bytes() -> usize {
    heap_size() - get_occupied_heap_size()
}

fn get_free_heap_percentage() -> f64 {
    (get_free_heap_size_in_bytes() as f64 / heap_size() as f64) * 100.0
}

fn get_random_num(start: usize, end: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..=end)
}

fn wait_per_thread(barrier_clone: Arc<Barrier>) {
    barrier_clone.wait();
}

fn traverse_and_check_buffer(buf: &(*mut u8, usize, String)) -> bool {
    if buf.2 != compute_sha256_hex(buf.0, buf.1) {
        return false;
    }
    return true;
}

fn select_and_check_random_buffer_contents(array_of_vectors: &Vec<(*mut u8, usize, String)>) {
    /* This function selects a random number of buffers and then calls
     * traverse_and_check_buffer which checks random contents of the set of
     * randomly selected buffers
     */
    let num_active_vectors = array_of_vectors.len();
    if num_active_vectors > 0 {
        let random_buffer_check_count = get_random_num(1, MAX_BUFFER_CHECKS_PER_THREAD_ITERATION);
        for _i in 1..=random_buffer_check_count {
            let random_buffer_index_to_check = get_random_num(0, array_of_vectors.len() - 1);
            assert!(traverse_and_check_buffer(
                &(array_of_vectors[random_buffer_index_to_check]),
            ));
        }
    }
}

fn delete_random_buffer(array_of_vectors: &mut Vec<(*mut u8, usize, String)>) {
    let num_active_vectors = array_of_vectors.len();
    if num_active_vectors > 0 {
        let random_index_to_delete = get_random_num(0, array_of_vectors.len() - 1);
        let len = array_of_vectors[random_index_to_delete].1;

        unsafe {
            dealloc(
                array_of_vectors[random_index_to_delete].0,
                Layout::from_size_align(len, ALIGN).unwrap(),
            );
        }
        array_of_vectors.remove(random_index_to_delete);
        update_occupied_heap_size_on_delete(len);
    }
}

fn add_new_buffer(array_of_vectors: &mut Vec<(*mut u8, usize, String)>) -> bool {
    /* This function assumes that the percentage of free heap space is more
     * than MIN_ALLOWED_FREE_HEAP_PERCENTAGE
     */

    let random_size = get_random_num(1, PER_THREAD_PER_BUFFER_MAX_SIZE);

    // Create a layout based on the size and alignment
    let layout = Layout::from_size_align(random_size, ALIGN).unwrap();

    // Allocate memory using the global allocator
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        return false;
    }

    for i in 0..=random_size - 1 {
        let random_byte = get_random_num(0, u8::MAX as usize) as u8;
        unsafe {
            ptr::write(ptr.offset(i as isize), random_byte);
        }
    }

    array_of_vectors.push((ptr, random_size, compute_sha256_hex(ptr, random_size)));
    update_occupied_heap_size_on_addition(random_size);
    return true;
}

fn compute_sha256_hex(ptr: *const u8, size: usize) -> String {
    let data = unsafe { slice::from_raw_parts(ptr, size) };
    // Create a SHA-256 hasher object
    let mut hasher = Sha256::new();

    // Update the hasher with the data
    hasher.update(data);

    // Finalize the hasher and get the result
    let result = hasher.finalize();

    // Convert the result into a hexadecimal string
    format!("{:x}", result)
}

fn worker_thread(tid: i32, barrier_clone: Arc<Barrier>) {
    /* Wait for all the threads to be created and then start together */
    wait_per_thread(barrier_clone);

    let mut array_of_vectors: Vec<(*mut u8, usize, String)> = Vec::new();

    /* Once the thread's allocation and deallocation operations begin, we
     * shouldn't take any lock as the allocator that we trying to test is a
     * multithreaded allocator and we should allow as many threads as possible
     * to get the lock.
     */
    for _i in 1..=MAX_ITERATIONS_PER_THREAD {
        let ran_choice = get_random_num(0, NUM_OPERATION_CHOICES - 1);

        match ran_choice {
            0 => {
                select_and_check_random_buffer_contents(&array_of_vectors);
                println!("T-{} check", tid);
            }
            1..=2 => {
                /* Although  get_free_heap_percentage() is thread safe, this
                 * match case may not be completely thread safe as we are only
                 * interested in an approximate value of the remaining free space
                 * percentage.
                 */
                if get_free_heap_percentage() > MIN_ALLOWED_FREE_HEAP_PERCENTAGE {
                    assert!(add_new_buffer(&mut array_of_vectors));
                    println!("T-{} allocate", tid);
                } else {
                    println!("T-{} SKIP", tid);
                }
            }
            3 => {
                delete_random_buffer(&mut array_of_vectors);
                println!("T-{} delete", tid);
            }
            _ => {
                panic!("Invalid random operation choice done");
            }
        }
    }
}

fn spawn_threads(thread_count: i32) {
    let mut handles = vec![];

    let barrier = Arc::new(Barrier::new(thread_count as usize));
    for i in 0..thread_count {
        /* Spawn a thread that waits till all threads are created */
        let barrier_clone = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            worker_thread(i, barrier_clone);
        });
        handles.push(handle);
    }

    /* Wait for all threads to finish */
    for handle in handles {
        handle.join().unwrap();
    }
}

fn start_tests() {
    let num_threads = NUM_THREADS;
    spawn_threads(num_threads as i32);
    println!("All {} threads completed", num_threads);
}

fn main() {
    start_tests();
}
