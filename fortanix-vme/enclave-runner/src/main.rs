use enclave_runner::server::Server;
use fortanix_vme_abi::SERVER_PORT;

fn main() {
    let (server_thread, _port) = Server::run(SERVER_PORT)
                                        .expect("Server failed");
    server_thread.join().expect("Server panicked");
}
