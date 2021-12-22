use fortanix_vme_runner::Server;
use fortanix_vme_abi::SERVER_PORT;
use std::io::ErrorKind;

fn main() {
    env_logger::init();

    match Server::run(SERVER_PORT) {
        Ok(handle)                                   => { handle.join().unwrap(); },
        Err(e) if e.kind() == ErrorKind::AddrInUse   => println!("Server failed. Do you already have a runner running on vsock port {}? (Error: {:?})", SERVER_PORT, e),
        Err(e)                                       => println!("Server failed. Error: {:?}", e),
    }
}
