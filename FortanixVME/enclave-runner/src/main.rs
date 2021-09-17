use enclave_runner::server::{Server, Tcp, Vsock};
use fortanix_vme_abi::SERVER_PORT;
use std::env;
use std::process;

fn main() {
    let (server_thread, _port) = if env::args().any(|arg| arg == "--vsock") {
        let vsock_server: Server<Vsock> = Server::new(Some(SERVER_PORT));
        vsock_server
            .run()
            .expect("Server failed")
    } else if env::args().any(|arg| arg == "--tcp") {
        let vsock_server: Server<Tcp> = Server::new(Some(SERVER_PORT));
        vsock_server
            .run()
            .expect("Server failed")
    } else {
        println!("Usage: enclave-runner {{--vsock|--tcp}}");
        process::exit(-1)
    };
    server_thread.join().expect("Server paniced");
}
