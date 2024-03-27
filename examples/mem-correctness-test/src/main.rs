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
 * So this basically runs for a long time and should never crash
 */

use core::arch::asm;
use rand::Rng;
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

extern "C" {
    static HEAP_BASE: u64;
    static HEAP_SIZE: usize;
}

const TO_KB: usize = 1024;
const TO_MB: usize = TO_KB * 1024;
const TO_GB: usize = TO_MB * 1024;

const NUM_OPERATION_CHOICES: usize = 4;
static HEAP_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

/* Set of configurable parameters. These will adjusted as necessary while
 * recording the performance numbers. Since this test will be in CI, I have
 * kept the parameters to be less memory intensive.
 */
const NUM_CPUS: usize = 2;
/* PER_THREAD_PER_BUFFER_MAX_SIZE is max size of a buffer that a thread can allocate
 * on each call to add_new_buffer() function. Higher the value, more will be
 * the total memory consumption and more time taken by the test.
 */
const PER_THREAD_PER_BUFFER_MAX_SIZE: usize = 4 * TO_KB;
/* MAX_BUFFER_CHECKS_PER_THREAD_ITERATION is the maximum number of buffers to
 * check on each call to select_and_check_random_buffer_contents()
 */
const MAX_BUFFER_CHECKS_PER_THREAD_ITERATION: usize = 8;
/* MAX_INDEX_CHECKS_PER_BUFFER is the number of indices/locations to check
 * per buffer.
 */
const MAX_INDEX_CHECKS_PER_BUFFER: usize = 1 << 16;
/* MIN_ALLOWED_FREE_HEAP_PERCENTAGE is the fraction free memory below which
 * we will allow the vector allocations to fail
 */
const MIN_ALLOWED_FREE_HEAP_PERCENTAGE: f64 = 10.0;
/* MAX_ITERATIONS_PER_THREAD is the number of operations per thread (1 operation per
 * per iteration)
 */
const MAX_ITERATIONS_PER_THREAD: usize = 32;

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

#[inline(always)]
pub(crate) unsafe fn rel_ptr_mut<T>(offset: u64) -> *mut T {
    (image_base() + offset) as *mut T
}

/* Returns the base memory address of the heap */
pub(crate) fn heap_base() -> *const u8 {
    unsafe { rel_ptr_mut(HEAP_BASE) }
}

/* Returns the size of the heap */
pub(crate) fn heap_size() -> usize {
    unsafe { HEAP_SIZE }
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

fn wait_per_thread(pair_clone: Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cvar) = &*pair_clone;
    let mut started = lock.lock().unwrap();
    while !*started {
        started = cvar.wait(started).unwrap();
    }
    drop(started);
}

fn wakeup_all_child_threads(pair_clone: Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cvar) = &*pair_clone;
    let mut started = lock.lock().unwrap();
    *started = true;
    cvar.notify_all();
    drop(started);
}

fn traverse_and_check_buffer(buf: &Vec<usize>, magic_num_to_check: usize) {
    let num_indices_checks = get_random_num(1, MAX_INDEX_CHECKS_PER_BUFFER);
    for _i in 1..=num_indices_checks {
        /* Check for random indices and number of such indices is  num_indices_checks
         * Please note that depending on the number random number generator, we
         * can check for the same index multiple times. We could have checked
         * for all the indices but that would be too time consuming
         */
        if buf[get_random_num(0, buf.len() - 1)] != magic_num_to_check {
            panic!("Corruption detected in traverse_and_check_buffer");
        }
    }
}

fn select_and_check_random_buffer_contents(
    array_of_vectors: &Vec<Vec<usize>>,
    magic_num_to_check: usize,
) {
    /* This function selects a random number of buffers and then calls
     * traverse_and_check_buffer which checks random contents of the set of
     * randomly selected buffers
     */
    let num_active_vectors = array_of_vectors.len();
    if num_active_vectors > 0 {
        let random_buffer_check_count = get_random_num(1, MAX_BUFFER_CHECKS_PER_THREAD_ITERATION);
        for _i in 1..=random_buffer_check_count {
            let random_buffer_index_to_check = get_random_num(0, array_of_vectors.len() - 1);
            traverse_and_check_buffer(
                &(array_of_vectors[random_buffer_index_to_check]),
                magic_num_to_check,
            );
        }
    }
}

fn delete_random_buffer(array_of_vectors: &mut Vec<Vec<usize>>) {
    let num_active_vectors = array_of_vectors.len();
    if num_active_vectors > 0 {
        let random_index_to_delete = get_random_num(0, array_of_vectors.len() - 1);
        let len = &array_of_vectors[random_index_to_delete].len() * mem::size_of::<i32>();
        array_of_vectors.remove(random_index_to_delete);
        update_occupied_heap_size_on_delete(len);
    }
}

fn add_new_buffer(array_of_vectors: &mut Vec<Vec<usize>>, magic_num_to_check: usize) {
    /* This function assumes that the percentage of free heap space is more
     * than MIN_ALLOWED_FREE_HEAP_PERCENTAGE
     */

    let random_size = get_random_num(mem::size_of::<usize>() * 2, PER_THREAD_PER_BUFFER_MAX_SIZE)
        / mem::size_of::<usize>();
    let mut tmp: Vec<usize> = Vec::with_capacity(random_size);
    tmp.resize(random_size, magic_num_to_check);
    array_of_vectors.push(tmp);
    update_occupied_heap_size_on_addition(random_size * mem::size_of::<usize>());
}

fn worker_thread(tid: i32, pair_clone: Arc<(Mutex<bool>, Condvar)>, magic_num_to_check: usize) {
    /* Wait for all the threads to be created and then start together */
    wait_per_thread(pair_clone);

    let mut array_of_vectors: Vec<Vec<usize>> = Vec::new();

    /* Once the thread's allocation and deallocation operations begin, we
     * shouldn't take any lock as the allocator that we trying to test is a
     * multithreaded allocator and we should allow as many threads as possible
     * to get the lock.
     */
    for _i in 1..=MAX_ITERATIONS_PER_THREAD {
        let ran_choice = get_random_num(0, NUM_OPERATION_CHOICES - 1);

        match ran_choice {
            0 => {
                select_and_check_random_buffer_contents(&array_of_vectors, magic_num_to_check);
                println!("T-{} check", tid);
            }
            1..=2 => {
                /* Although  get_free_heap_percentage() is thread safe, this
                 * match case may not be completely thread safe as we are only
                 * interested in an approximate value of the remaining free space
                 * percentage.
                 */
                if get_free_heap_percentage() > MIN_ALLOWED_FREE_HEAP_PERCENTAGE {
                    add_new_buffer(&mut array_of_vectors, magic_num_to_check);
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

fn spawn_threads(thread_count: i32, magic_num_to_check: usize) {
    let mut handles = vec![];

    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    for i in 0..thread_count {
        // Spawn a thread that waits until the condition is met
        let pair_clone = Arc::clone(&pair);
        let handle = thread::spawn(move || {
            worker_thread(i, pair_clone, magic_num_to_check);
        });
        handles.push(handle);
    }

    /* Start all the threads */
    wakeup_all_child_threads(pair);

    /* Wait for all threads to finish */
    for handle in handles {
        handle.join().unwrap();
    }
}

fn get_num_processors() -> usize {
    //num_cpus::get()
    /* ToDo: Currently it tests with a hardcoded value. We need to add a
     * special service to make it work properly.
     */
    NUM_CPUS
}

/* If there are n processors available, we will record the numbers with,2n threads,
 * then n threads, then n/2 and so on.
 */
fn start_tests() {
    let magic_num_to_check = get_random_num(1, usize::MAX);
    let num_processors = get_num_processors();
    let num_threads = num_processors;
    spawn_threads(num_threads as i32, magic_num_to_check);
    println!("All {} threads completed", num_threads);
}

fn main() {
    start_tests();
}
