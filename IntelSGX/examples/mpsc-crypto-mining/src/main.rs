extern crate easy_hash;

use easy_hash::{Sha256, Hasher, HashResult};
use std::thread;
use std::sync::{mpsc, Arc};
use std::sync::atomic::{AtomicBool, Ordering};

const BASE: usize = 42;
const THREADS: usize = 4;
static DIFFICULTY: &'static str = "000000";

struct Solution(usize, String);

fn verify_number(number: usize) -> Option<Solution> {
    let hash: String = Sha256::hash((number * BASE).to_string().as_bytes()).hex();
    if hash.ends_with(DIFFICULTY) {
        Some(Solution(number, hash))
    } else {
        None
    }
}

fn search_for_solution(start_at: usize, sender: mpsc::Sender<Solution>, is_solution_found: Arc<AtomicBool>) {
    let mut iteration_no = 0;
    for number in (start_at..).step_by(THREADS) {
        if let Some(solution) = verify_number(number) {
            is_solution_found.store(true, Ordering::Relaxed);
            match sender.send(solution) {
                Ok(_)  => {},
                Err(_) => println!("Receiver has stopped listening, dropping worker number {}.", start_at),
            }
            return;
        } else if iteration_no % 1000 == 0 && is_solution_found.load(Ordering::Relaxed) {
            return;
        }
        iteration_no += 1;
    }
}

fn main() {
    println!("Attempting to find a number, which - while multiplied by {} and hashed using SHA-256 - will result in a hash ending with {}. \nPlease wait...", BASE, DIFFICULTY);

    let is_solution_found = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::channel();
    
    /*
     * Here, we have 4 threads (as specified by the value of THREADS constant).
     * Thread 0 will start at number 0 and check 0, 4, 8,  12 and so on.
     * Thread 1 will start at number 1 and check 1, 5, 9,  13 and so on.
     * Thread 2 will start at number 2 and check 2, 6, 10, 14 and so on.
     * Thread 3 will start at number 3 and check 3, 7, 11, 15 and so on.
     * 
     * See the pattern? ;)
     * 
     * This way, we have 4 parallel threads of execution and we're sure
     * that each number will be examined exactly once.
     */
    for i in 0..THREADS {
        let sender_n = sender.clone();
        let is_solution_found = is_solution_found.clone();
        thread::spawn(move || {
            search_for_solution(i, sender_n, is_solution_found);
        });
    }
    
    match receiver.recv() {
        Ok(Solution(i, hash)) => {
            println!("Found the solution.");
            println!("The number is: {}.", i);
            println!("Result hash: {}.", hash);
        },
        Err(_) => panic!("Worker threads disconnected before the solution was found!"),
    }
}
