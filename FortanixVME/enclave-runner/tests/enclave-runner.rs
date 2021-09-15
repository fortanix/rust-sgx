use fortanix_vme_abi;
use std::thread;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[test]
fn test_connect() {
    let _ = thread::spawn(|| {
        let server = enclave_runner::server::Server::new();
        server.run().unwrap();
    });

    // Wait until server starts listening
    thread::sleep(Duration::from_millis(2000));

    // Signal to connect to the specified server
    let mut client = fortanix_vme_abi::Client::<TcpStream>::new().expect("Connection failed");
    let proxy_port = client.open_proxy_connection("google.com:80".to_string()).expect("Proxy connection failed");

    // Connect with proxy
    thread::sleep(Duration::from_millis(500));
    let mut proxy = TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).expect("Proxy failed");

    thread::sleep(Duration::from_millis(500));
    proxy.write(b"GET / HTTP/1.1\n\n").unwrap();
    proxy.flush().unwrap();
    let mut out = [0; 4000];
    proxy.read(&mut out).unwrap();
    let out = String::from_utf8(out.to_vec()).unwrap();
    assert!(out.contains("Google"));
}
