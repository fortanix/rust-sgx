use enclave_runner::server::Server;

fn main() {
    let server = Server::new();
    server.run().expect("Server failed");
}
