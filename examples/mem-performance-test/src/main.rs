// How to run:
// cargo run --features "mem_basic"   or just: cargo run
// cargo run --features "mem_hot"
// cargo run --features "mem_cold"
// cargo run --features "mem_hot,zero_after_alloc"

#![feature(allocator_api)]
#![feature(new_uninit)]
#![feature(vec_push_within_capacity)]


use std::alloc::AllocError;
//use std::env;
//use crate::error::Error;
//use std::fmt::Error;
//use std::error::Error;
//use std::path::Path;
use std::time::{Instant, Duration};
use std::mem;
// use std::mem::MaybeUninit;

static APP_NAME: &str = "mem-performance-test";

// Test Parameters
//    println!("    AllocFree: does alloc buf_size followed by free for n_sec");
//    println!("    AllocManyFreeManyCold: does buf_size allocations for a total of max_alloc ");
//    println!("      bytes followed of a free for all allocated buffers. after each run the ");
//    println!("      application exits.");
//    println!("    AllocManyFreeManyWarm: silmilar to AllocManyFreeManyCold but it ignores the ");
//    println!("      first run and run each buf_size without restarting the application.");

const POW: u32 = 3; // MIN_SIZE specified as power of 2.  8bytes = 2^3
const MIN_SIZE: usize = mem::size_of::<u64>();
// number of seconds to run each buf_size test. Ignored by cold tests.
const TEST_SEC: u32 = 30;
// maximum amount of memory to allocate. Specified in GiBi bytes.
const DEFAULT_MAX_MEM_ALLOC_SIZE: usize = gi_bi_bytes(1);


const PAGE_SIZE: usize = 4096;
const PAGE_STEP_U64: usize = PAGE_SIZE / mem::size_of::<u64>();

// IEC power of two values conversion
#[inline]
const fn ki_bi_bytes(val: usize) -> usize { val * 1024 as usize }
#[inline]
const fn me_bi_bytes(val: usize) -> usize { ki_bi_bytes (val) * 1024 as usize }
#[inline]
const fn gi_bi_bytes(val: usize) -> usize { me_bi_bytes (val) * 1024 as usize }


fn mem_alloc(buf_size: usize) -> Result<Box<[u64]>, AllocError> {

    let size = buf_size / mem::size_of::<u64>();

    // #[cfg(never)]
    #[cfg(not(feature = "zero_after_alloc"))]
    let mut buf = Box::<[u64]>::try_new_uninit_slice(size)?;
    #[cfg(feature = "zero_after_alloc")]
    let mut buf = Box::<[u64]>::try_new_zeroed_slice(size)?;

    // *** step on each page to make sure pages are allocated *** //
    // Note: needed even for the zeroed memory.
    let buf = unsafe {
        // touch every page
        for i in (0..size).step_by(PAGE_STEP_U64) {
            buf[i].as_mut_ptr().write(i as u64);
        }
     
        buf.assume_init()
    };

    Ok(buf)
}

fn alloc_free_loop(buf_size: usize, n_loops: u32) -> Result<Duration, AllocError> {
    let start = Instant::now();

    for _i in 0..n_loops {
        match mem_alloc(buf_size) {
            Ok(mem) => drop(mem),
            Err(err) => return Err(err),
        }
    }

    let end = Instant::now();

    Ok(end - start)
}

fn test_alloc_free(buf_size: usize, n_sec: u32) -> Result<f64, AllocError> {

    let max_secs = if n_sec > 0 { n_sec } else { 1 };
    let max_duration = Duration::from_secs(max_secs as u64);

    // calculate n_loops per second
    let mut loops_per_sec: u32 = 0;
    for i in 1..100 {
        let duration = alloc_free_loop(buf_size, i)?;
//        println!("ops {}, duration: {:#?}", i, duration.as_secs_f64());
        if duration > Duration::from_micros(1) {
            loops_per_sec = if duration > Duration::from_secs(1) { 
                i
            } else {
                (i as f64 / duration.as_secs_f64()) as u32
            };
            break;
        }
    }
    if loops_per_sec < 1 { return Err(AllocError) }
    assert!((loops_per_sec as u64 * max_secs as u64) <= (std::u32::MAX as u64));
//    println!("size: {} loops per second {}", buf_size, loops_per_sec);

    // run test
    let mut total_duration = Duration::from_secs(0);
    let mut total_loops: u64 = 0;
    while total_duration < max_duration {
        let duration = alloc_free_loop(buf_size, loops_per_sec)?;
        total_duration += duration;
        total_loops += loops_per_sec as u64;
//        print!("size: {}, {} of {}        \r", buf_size, _i, n_loops);
    }
    debug_assert_ne!(total_loops, 0);
    assert!(total_duration.as_secs_f64() > 0.0);

    // return operations per second
    Ok(total_loops as f64 / total_duration.as_secs_f64() )
}

#[allow(dead_code)]
fn alloc_free_via_vector(vec: &mut Vec<Box<[u64]>>, buf_size: usize, max_mem_alloc: usize)
                         -> Result<(Duration, u64), AllocError> {
    debug_assert_ne!(buf_size, 0);

    // lets start with the default max data size addressable by vec, if not set already
    let n_els = max_mem_alloc / buf_size;
    debug_assert_ne!(n_els, 0);
    if vec.capacity() < n_els { 
        vec.reserve(n_els - vec.capacity());
    }
    if vec.len() <= 0 { vec.clear(); } // j.i.c. - expected to be empty

    // run test
    let total_ops;
    let mut i = 0;
    let start = Instant::now();
    // *** Alloc *** //
    while let Ok(mem) = mem_alloc(buf_size) {
        if vec.push_within_capacity(mem).is_err() {
            break;
        }
        // vec.push(&mut mem);
        i += 1;
        if i >= n_els { 
            break; 
        }
    }
    total_ops = i;

    // *** Free *** //
    for _ in 0..total_ops {
        if let Some(mem) = vec.pop() {
            drop(mem);
        }
    }
    let end = Instant::now();

    // *** now we can remove the elememts from the vector *** /
    vec.clear();

    debug_assert_ne!(total_ops, 0);
    let total_duration = end - start;
    assert!(total_duration.as_secs_f64() > 0.0);

    // return operations per second
    Ok((total_duration, total_ops as u64))
}

// if n_sec == 0, do a single run (ignore_first is ignored)
#[allow(dead_code)]
fn test_alloc_free_via_vector(buf_size: usize, n_sec: u32, ignore_first: bool) 
                              -> Result<f64, AllocError> {
    debug_assert_ne!(buf_size, 0);

    // lets start with the default max data size addressable by vec, if not set already
    let n_els = DEFAULT_MAX_MEM_ALLOC_SIZE / buf_size;
    debug_assert_ne!(n_els, 0);
    let mut vec: Vec<Box<[u64]>> = Vec::with_capacity(n_els);

    let mut total_duration = Duration::default();
    let mut total_operations: u64 = 0;
    let mut first = true;
    let start = Instant::now();
    loop {
        match alloc_free_via_vector(&mut vec, buf_size, DEFAULT_MAX_MEM_ALLOC_SIZE) {
            Ok((dur, oper)) => {
                debug_assert_ne!(oper, 0);
                if n_sec == 0 {
                    return Ok(oper as f64 / dur.as_secs_f64());
                }
                if ignore_first && first {
                    first = false;
                } else {
                    total_duration += dur;
                    total_operations += oper;
                }
            },
            Err(err) => {
                println!("alloc_free_via_vector failed with {err}");
                return Err(err);
            },
        }
        let dur = Instant::now() - start;
        if dur.as_secs_f64() as u64 > n_sec as u64 {
            break;
        }
    }

    return Ok(total_operations as f64 / total_duration.as_secs_f64());
}

fn run_tests(size: usize, test_sec: u32) -> Result<f64, AllocError> {
    #[cfg(feature = "mem_hot")]
        return test_alloc_free_via_vector(size, test_sec, false);

    #[cfg(feature = "mem_cold")]
        return test_alloc_free_via_vector(size, test_sec, true);

    return test_alloc_free(size, test_sec);
}

fn get_test_name() -> &'static str {
    #[cfg(feature = "mem_hot")]
        return "Memory Hot Tests";

    #[cfg(feature = "mem_cold")]
        return "Memory Cold Tests (single pass)";

    return "Basic Memory tests";
}

fn get_zero_after_alloc_txt() -> &'static str {
    #[cfg(feature = "zero_after_alloc")]
        return "zero_after_alloc";

    return "!zero_after_alloc";
}

fn main() {

    println!("{}: {} ({})", APP_NAME, get_test_name(), get_zero_after_alloc_txt());

    let mut pow = POW;
    let min_size = MIN_SIZE;
    let test_sec = TEST_SEC;

    let mut size = min_size;
    while size <= DEFAULT_MAX_MEM_ALLOC_SIZE {
        match run_tests(size, test_sec) {
            Ok(ops) => {
                println!("size: 2^{:-2} = {:11.2} ops, {:11.2} MiBi/s",
                        pow, ops, ops * (size as f64 / me_bi_bytes(1) as f64));
            },
            Err(err) => println!("Operation failed for size: 2^{:2}: {}", pow, err),
        }
        size *= 2 as usize;
        pow += 1;
    }

}
