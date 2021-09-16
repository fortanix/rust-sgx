use enclave_runner::server::{Server, Tcp, Vsock};
use std::env;

fn main() {
    if env::args().any(|arg| arg == "--vsock") {
        let vsock_server: Server<Vsock> = Server::new();
        vsock_server.run().expect("Server failed");
    } else if env::args().any(|arg| arg == "--tcp") {
        let vsock_server: Server<Tcp> = Server::new();
        vsock_server.run().expect("Server failed");
    } else {
        println!("Usage: enclave-runner {{--vsock|--tcp}}");
    }
}
