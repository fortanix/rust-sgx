use std::{thread, time};

fn main() {
    for i in 0..30 {
        println!("{}: Hello, world!", i);
        thread::sleep(time::Duration::from_secs(1));
    }

    println!("Byte bye!");
}
