/* Test description:
 * This test tries to record the performance numbers with the memory allocator
 * used in EDP. The steps are as follows:
 * Create n threads. Each threads will continuosly allocate a randomly sized
 * buffer, traverse random locations in the buffer and then free it.
 *
 * There are 3 types of threads, small, medium and large. Depending on the type
 * the small threads will allocate and deallocate small sized buffers, and the
 * large threads will allocate and deallocate large sized buffers. The buffer
 * sizes and number of checks are all controlled by some parameters/constants
 * which are there a couple of lines below.
 *
 * The todos before running this test is there in the description of
 * https://fortanix.atlassian.net/browse/RTE-36 (under the heading
 * "Instructions on how to run the test:" )
 */
/*
The performance results produced by this test were quite random to get a clear picture of
improvements between dlmalloc and snmalloc allocator. In order to reduce the randomness
of the tests, use feature flag "reduce_randomness" - RTE-85
*/

use rand::Rng;
use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;
#[derive(Debug, PartialEq)]
enum MemSize {
    Large,
    Medium,
    Small,
}
/* These 3 variables will store the average latency of allocation+access+deallocation
 * per thread type i.e, if there are 2 small threads, 3 medium threads and
 * 4 large threads each of which runs 10, 20 and 30 times, then
 * avg_duration_small_thread will store average latency of 2*10=20 iterations,
 * avg_duration_medium_thread will store average latency of 3*20=60 iterations,
 * and avg_duration_large_thread will store average latency of 4*30=120 iterations
 */
struct Counters {
    avg_duration_small_thread: f64,
    avg_duration_medium_thread: f64,
    avg_duration_large_thread: f64,
    global_average: f64,
}

const PAGE_SIZE: usize = 4096;
const TO_KB: usize = 1024;
const TO_MB: usize = TO_KB * 1024;
const TO_GB: usize = TO_MB * 1024;

/* Set of configurable parameters. These will adjusted as necessary while
 * recording the performance numbers.
 * TODO: Replace the hard coded parameters with command line arguments.
 */

/* This denotes the number of cpus in the system in which the test is being run.
 * This test will create as many number of threads as there are number of CPUs.
 */
const NUM_CPUS: usize = 2;

/* This thread creates 3 types of threads. Small, medium and large. Each type of
 * thread will run the loop of allocation and deallocation different number of
 * times. LIMIT_SMALL_THREAD, LIMIT_MEDIUM_THREAD, LIMIT_LARGE_THREAD denotes
 * the number of times small threads, medium threads and large threads run the
 * loop respectively.
 */
const LIMIT_SMALL_THREAD: i32 = 2;
const LIMIT_MEDIUM_THREAD: i32 = 2;
const LIMIT_LARGE_THREAD: i32 = 2;

/* Each type of thread namely, small, medium and large allocates different sizes
 * of memory and hence they have different scan intervals. This scan interval is
 * used in the traverse_buffer function. Large threads have large buffers and
 * their intervals are larger compared to small threads which allocate smaller
 * buffer. SCAN_INTERVAL_SMALL_THREAD, SCAN_INTERVAL_MEDIUM_THREAD, and
 * SCAN_INTERVAL_LARGE_THREAD denote the scan intervals for small threads,
 * medium threads and large threads respectively.
 */
const SCAN_INTERVAL_SMALL_THREAD: usize = 1 * TO_KB;
const SCAN_INTERVAL_MEDIUM_THREAD: usize = 1 * TO_MB;
const SCAN_INTERVAL_LARGE_THREAD: usize = 1 * TO_MB;


/* Each thread allocates a random sized buffer. The range of the random sizes
 * depend on the thread type namely small, medium and large.
 * SMALL_THREAD_MEM_START and SMALL_THREAD_MEM_END denote the minium and maximum
 * buffer size of small threads in KB respectively.
 *
 * MEDIUM_THREAD_MEM_START and MEDIUM_THREAD_MEM_END denote the minium and maximum
 * buffer size of medium threads in MB respectively.
 * LARGE_THREAD_MEM_START and LARGE_THREAD_MEM_END denote the minium and maximum
 * buffer size of large threads in GB respectively.
 */
const SMALL_THREAD_MEM_START: usize = 1; // in KB
const SMALL_THREAD_MEM_END: usize = 512; // in KB
const MEDIUM_THREAD_MEM_START: usize = 1; // in MB
const MEDIUM_THREAD_MEM_END: usize = 2; // in MB
const LARGE_THREAD_MEM_START: usize = 1; // in GB
const LARGE_THREAD_MEM_END: usize = 2; // in GB

/* In traverse_buffer function, we randomly pick up random number of indices in
 * in the buffer and access them. MAX_INDEX_CHECKS_PER_BUFFER denotes the maximum
 * number of checks per buffer. We don't traverse the entire buffer as it will
 * slow down each thread and the threads won't be able to exihibit concurrency
 * during thread allocation and de allocation. Higher the value of
 * MAX_INDEX_CHECKS_PER_BUFFER, slower will be the threads and lesser will be
 * the concurrency.
 */
const MAX_INDEX_CHECKS_PER_BUFFER: usize = 32;

fn calculate_and_print_stat(
    shared_mutex_clone: Arc<Mutex<Counters>>,
    memsize: &MemSize,
    avg_thread_latency: f64,
) {
    /* TODO: Record some other statistical parameters like more detailed statistics
     * than just average, such as standard deviation, minimum and maximum time,
     * and p95/p99/p99.9 latency
     */
    //println!("thread {} took {}\n", _tid, avg_thread_latency);
    let mut data = shared_mutex_clone.lock().unwrap();
    /* Please note this is an intermediate value. Once we get the sum of individual
     * averages of all the threads, then we will divide it by the frequency of
     * the corresponding thread memsize type.
     */
    match memsize {
        MemSize::Large => {
            data.avg_duration_large_thread += avg_thread_latency;
        }
        MemSize::Medium => {
            data.avg_duration_medium_thread += avg_thread_latency;
        }
        MemSize::Small => {
            data.avg_duration_small_thread += avg_thread_latency;
        }
    };
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

fn traverse_buffer(buf: *mut u8, size: usize, _scan_interval: usize) {
    let num_indices_checks: usize;
    #[cfg(feature = "reduce_randomness")]
    {
        num_indices_checks = 10;
    }
    #[cfg(not(feature = "reduce_randomness"))]
    {
        num_indices_checks= get_random_num(1, MAX_INDEX_CHECKS_PER_BUFFER);
    }
    for _i in 1..=num_indices_checks {
        /* Check for random indices and number of such indices is  num_indices_checks
         * Please note that depending on the number random number generator, we
         * can check for the same index multiple times. We could have checked
         * for all the indices but that would be too time consuming
         */
        let index: usize;
        #[cfg(feature = "reduce_randomness")]
        {
            index = _i * 10 % size;
        }
        #[cfg(not(feature = "reduce_randomness"))]
        {
            index = get_random_num(0, size - 1);
        }
        unsafe {
            ptr::write(buf.offset(index as isize), 1);
        }
    }
}

fn worker_thread(
    shared_mutex_clone: Arc<Mutex<Counters>>,
    memsize: MemSize,
    pair_clone: Arc<(Mutex<bool>, Condvar)>,
) {
    /* Wait for all the threads to be created and then start together */
    wait_per_thread(pair_clone);

    let mut count = 0;
    let mut tot_time_ns = 0;

    /* Once the thread's allocation and deallocation operations begin, we
     * shouldn't take any lock as the allocator that we trying to test is a
     * multithreaded allocator and we should allow as many threads as possible
     * to get the lock.
     */
    loop {
        /* Create a random size depending on the memory type */
        let (scan_interval, mut size, limit) = match memsize {
            MemSize::Large => {
                (
                    SCAN_INTERVAL_LARGE_THREAD,
                    TO_GB * get_random_num(LARGE_THREAD_MEM_START, LARGE_THREAD_MEM_END),
                    LIMIT_LARGE_THREAD,
                )
            }
            MemSize::Medium => {
                (
                    SCAN_INTERVAL_MEDIUM_THREAD,
                    TO_MB * get_random_num(MEDIUM_THREAD_MEM_START, MEDIUM_THREAD_MEM_END),
                    LIMIT_MEDIUM_THREAD,
                )
            }
            MemSize::Small => {
                (
                    SCAN_INTERVAL_SMALL_THREAD,
                    TO_KB * get_random_num(SMALL_THREAD_MEM_START, SMALL_THREAD_MEM_END),
                    LIMIT_SMALL_THREAD,
                )
            }
        };

        let start_time = Instant::now();

        /* Create an array of x GB where x is a random number between 1 to 4 */

        // Create a layout based on the size and alignment
        let align: usize;
        #[cfg(feature = "reduce_randomness")]
        {
            align = PAGE_SIZE;
            size = match memsize {
                MemSize::Large => crate::TO_GB * 1,
                MemSize::Medium =>  crate::TO_MB * 1,
                MemSize::Small => crate::TO_KB * 1
            }
        }
        #[cfg(not(feature = "reduce_randomness"))]
        {
            align = get_random_num(2, PAGE_SIZE).next_power_of_two();

        }
        let layout = Layout::from_size_align(size, align).unwrap();

        // Allocate memory using the global allocator
        let ptr = unsafe { alloc(layout) };
        assert!(!ptr.is_null());

        /* Traverse and access the entire buffer so that pages are allocated */
        traverse_buffer(ptr, size, scan_interval);

        /* deallocate */
        unsafe {
            dealloc(ptr, layout);
        }

        /* calculate the metrics */
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        tot_time_ns += duration.as_nanos();

        count = count + 1;
        if count >= limit {
            break;
        }
    }

    /* At this point the thread's allocation and deallocation operations are
     * completed and hence it is okay to take a lock.
     */

    let avg_thread_latency = tot_time_ns as f64 / count as f64;

    let shared_mutex_clone_2 = Arc::clone(&shared_mutex_clone);
    calculate_and_print_stat(shared_mutex_clone_2, &memsize, avg_thread_latency);
}

fn spawn_threads(thread_count: i32) {
    let mut handles = vec![];
    let shared_variable = Arc::new(Mutex::new(Counters {
        avg_duration_large_thread: 0.0,
        avg_duration_medium_thread: 0.0,
        avg_duration_small_thread: 0.0,
        global_average: 0.0,
    }));

    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let (mut num_small_threads, mut num_medium_threads, mut num_large_threads) = (0, 0, 0);
    for i in 0..thread_count {
        let shared_mutex_clone = Arc::clone(&shared_variable);
        // Spawn a thread that waits until the condition is met
        let pair_clone = Arc::clone(&pair);
        let memtype;

        match i % 2 {
            0 => {
                memtype = MemSize::Small;
                num_small_threads += 1;
            }
            1 => {
                memtype = MemSize::Medium;
                num_medium_threads += 1;
            }
            2 => {
                memtype = MemSize::Large;
                num_large_threads += 1;
            }
            _ => return,
        };

        let handle = thread::spawn(move || {
            worker_thread(shared_mutex_clone, memtype, pair_clone);
        });
        handles.push(handle);
    }

    /* Start all the threads */
    wakeup_all_child_threads(pair);

    /* Wait for all threads to finish */
    for handle in handles {
        handle.join().unwrap();
    }

    /* Calculate final means */
    let mut data = shared_variable.lock().unwrap();
    if num_large_threads != 0 {
        data.avg_duration_large_thread = data.avg_duration_large_thread / num_large_threads as f64;
    }
    data.avg_duration_medium_thread = data.avg_duration_medium_thread / num_medium_threads as f64;
    data.avg_duration_small_thread = data.avg_duration_small_thread / num_small_threads as f64;

    data.global_average = (data.avg_duration_small_thread
        * num_small_threads as f64
        * LIMIT_SMALL_THREAD as f64
        + data.avg_duration_medium_thread * num_medium_threads as f64 * LIMIT_MEDIUM_THREAD as f64
        + data.avg_duration_large_thread * num_large_threads as f64 * LIMIT_LARGE_THREAD as f64)
        / (num_large_threads * LIMIT_LARGE_THREAD
            + num_medium_threads * LIMIT_MEDIUM_THREAD
            + num_small_threads * LIMIT_SMALL_THREAD) as f64;
    println!(
        "{},{},{},{},{}",
        thread_count,
        data.avg_duration_small_thread,
        data.avg_duration_medium_thread,
        data.avg_duration_large_thread,
        data.global_average
    );
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
    println!("NUM_THREADS,LATENCY_SMALL_THREADS,LATENCY_MEDIUM_THREADS,LATENCY_LARGE_THREADS,GLOBAL_AVERAGE");
    let num_processors = get_num_processors();
    let mut num_threads = num_processors * 2;
    while num_threads >= 3 {
        spawn_threads(num_threads as i32);
        num_threads = num_threads >> 1;
    }
}

fn main() {
    start_tests();
}
