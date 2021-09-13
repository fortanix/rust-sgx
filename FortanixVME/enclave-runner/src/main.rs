use enclave_runner::server::Server;

fn main() {
    println!("Starting enclave runner...");
    let server = Server::new();
    server.run().expect("Server failed");
}
