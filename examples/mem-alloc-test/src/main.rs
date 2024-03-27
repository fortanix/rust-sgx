use rand::Rng;
use num_cpus;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Instant};

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
 * recording the performance numbers
 */
const NUM_CPUS: usize = 2;

const LIMIT_SMALL_THREAD: i32 = 2;
const LIMIT_MEDIUM_THREAD: i32 = 2;
const LIMIT_LARGE_THREAD: i32 = 2;

const SCAN_INTERVAL_SMALL_THREAD: usize = 1 * TO_KB;
const SCAN_INTERVAL_MEDIUM_THREAD: usize = 1 * TO_MB;
const SCAN_INTERVAL_LARGE_THREAD: usize = 1 * TO_MB;

const SMALL_THREAD_MEM_START: usize = 1;
const SMALL_THREAD_MEM_END: usize = 512;
const MEDIUM_THREAD_MEM_START: usize = 1;
const MEDIUM_THREAD_MEM_END: usize = 2;
const LARGE_THREAD_MEM_START: usize = 1;
const LARGE_THREAD_MEM_END: usize = 2;

const MAX_INDEX_CHECKS_PER_BUFFER: usize = 32;

fn calculate_and_print_stat(
    shared_mutex_clone: Arc<Mutex<Counters>>,
    tid: i32,
    memsize: &MemSize,
    avg_thread_latency: f64,
) {
    /* TODO: Record some other statistical parameters like more detailed statistics
     * than just average, such as standard deviation, minimum and maximum time,
     * and p95/p99/p99.9 latency
     */
    //println!("thread {} took {}\n", tid, avg_thread_latency);
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

fn traverse_buffer(buf: &mut Vec<i32>, scan_interval: usize) {
    let mut ptr = 0;
    let num_indices_checks = get_random_num(1, MAX_INDEX_CHECKS_PER_BUFFER);
    for i in 1..=num_indices_checks {
        /* Check for random indices and number of such indices is  num_indices_checks
         * Please note that depending on the number random number generator, we
         * can check for the same index multiple times. We could have checked
         * for all the indices but that would be too time consuming
         */
        let index = get_random_num(0, buf.len() - 1);
        buf[index] = buf[index] * 2;
    }
}

fn worker_thread(
    tid: i32,
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
        let (scan_interval, size, limit) = match memsize {
            MemSize::Large => {
                /* buffer size will be from 1GB to 4GB */
                (
                    SCAN_INTERVAL_LARGE_THREAD,
                    TO_GB * get_random_num(LARGE_THREAD_MEM_START, LARGE_THREAD_MEM_END),
                    LIMIT_LARGE_THREAD,
                )
            }
            MemSize::Medium => {
                /* buffer size will be from 8MB to 128 */
                (
                    SCAN_INTERVAL_MEDIUM_THREAD,
                    TO_MB * get_random_num(MEDIUM_THREAD_MEM_START, MEDIUM_THREAD_MEM_END),
                    LIMIT_MEDIUM_THREAD,
                )
            }
            MemSize::Small => {
                /* buffer size will be from 1KB to 512KB */
                (
                    SCAN_INTERVAL_SMALL_THREAD,
                    TO_KB * get_random_num(SMALL_THREAD_MEM_START, SMALL_THREAD_MEM_END),
                    LIMIT_SMALL_THREAD,
                )
            }
        };

        let start_time = Instant::now();

        /* Create an array of x GB where x is a random number between 1 to 4 */
        let mut large_vector = Vec::with_capacity(size);
        large_vector.resize(size, 0);

        /* Traverse and access the entire buffer so that pages are allocated */
        traverse_buffer(&mut large_vector, scan_interval);

        /* deallocate */
        drop(large_vector);

        /* calculate the metrics */
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        tot_time_ns += duration.as_nanos();

        count = count + 1;
        if (count >= limit) {
            break;
        }
    }

    /* At this point the thread's allocation and deallocation operations are
     * completed and hence it is okay to take a lock.
     */

    let avg_thread_latency = tot_time_ns as f64 / count as f64;

    let shared_mutex_clone_2 = Arc::clone(&shared_mutex_clone);
    calculate_and_print_stat(shared_mutex_clone_2, tid, &memsize, avg_thread_latency);
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
        let mut memtype;

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
            worker_thread(i, shared_mutex_clone, memtype, pair_clone);
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
    if (num_large_threads != 0) {
        data.avg_duration_large_thread = data.avg_duration_large_thread / num_large_threads as f64;
    }
    data.avg_duration_medium_thread = data.avg_duration_medium_thread / num_medium_threads as f64;
    data.avg_duration_small_thread = data.avg_duration_small_thread / num_small_threads as f64;

    data.global_average = (data.avg_duration_small_thread * num_small_threads as f64 * LIMIT_SMALL_THREAD as f64
        + data.avg_duration_medium_thread * num_medium_threads as f64 * LIMIT_MEDIUM_THREAD as f64
        + data.avg_duration_large_thread * num_large_threads as f64 * LIMIT_LARGE_THREAD as f64)
        / (num_large_threads * LIMIT_LARGE_THREAD +
            num_medium_threads * LIMIT_MEDIUM_THREAD + num_small_threads * LIMIT_SMALL_THREAD) as f64;
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
    let mut num_processors = get_num_processors();
    let mut num_threads = num_processors * 2;
    while (num_threads >= 3) {
        spawn_threads(num_threads as i32);
        num_threads = num_threads >> 1;
    }
}

fn main() {
    start_tests();
}
