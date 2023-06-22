# Breaking vdso enclave execution through user handler and signals

A `user_handler` is installed with the vsdo through the `SgxEnclaveRun` struct. A signal handler is installed as well to avoid that the process aborts when a signal is received. Unfortunately, the following program does not enter the installed `user_handler` when executing `kill -s 2 $(pidof ftxsgx-runner)`.

```
use std::{sync::mpsc, thread};

fn main() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        tx.send(()).unwrap();
        loop {}
    });
    rx.recv().unwrap();
    println!("Exiting main thread");
}
```
