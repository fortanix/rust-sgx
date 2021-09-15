use enclave_runner::server::{Server, Tcp};

fn main() {
    println!("Starting enclave runner...");
    let server: Server<Tcp> = Server::new();
    server.run().expect("Server failed");
}
