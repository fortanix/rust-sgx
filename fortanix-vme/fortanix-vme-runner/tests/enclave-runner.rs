use fortanix_vme_runner::server::Server;
use fortanix_vme_abi;
use std::io::Write;
use vsock::Std;

#[test]
fn outgoing_connections() {
    let (_server_thread, server_port) = Server::run(0).unwrap();

    // Signal to connect to the specified server
    let mut client = fortanix_vme_abi::Client::<Std>::new(server_port).expect("Connection failed");
    let mut proxy = client.open_proxy_connection("google.com:80".to_string()).expect("Proxy connection failed");

    proxy.write(b"GET / HTTP/1.1\n\n").unwrap();
    proxy.flush().unwrap();
    let mut out = [0; 4000];
    proxy.read(&mut out).unwrap();
    let out = String::from_utf8(out.to_vec()).unwrap();
    assert!(out.contains("Google"));
}
