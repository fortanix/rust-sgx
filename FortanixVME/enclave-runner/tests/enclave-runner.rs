use enclave_runner::server::{Server, Tcp};
use fortanix_vme_abi;
use std::thread;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[test]
fn outgoing_connections() {
    let server: Server<Tcp> = enclave_runner::server::Server::new(None);
    let (_server_thread, server_port) = server.run().unwrap();

    // Wait until server starts listening
    thread::sleep(Duration::from_millis(500));

    // Signal to connect to the specified server
    let mut client = fortanix_vme_abi::Client::<TcpStream>::new(Some(server_port)).expect("Connection failed");
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

#[test]
fn incoming_connections() {
    let server: Server<Tcp> = enclave_runner::server::Server::new(None);
    let (_server_thread, server_port) = server.run().unwrap();

    // Wait until server starts listening
    thread::sleep(Duration::from_millis(500));

    // Start listening on a socket and tell the enclave runner to do the same and forward incoming
    // connections
    // This will be a vsock listener
    let mut client = fortanix_vme_abi::Client::<TcpStream>::new(Some(server_port)).expect("Connection failed");
    let (enclave_listener, parent_port) = client.bind_socket("localhost:0".to_string()).expect("Bind failed");

    thread::spawn(move || {
        // emulate enclave handling incoming connections
        for stream in enclave_listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buff = [0u8; 100];
            let n = stream.read(&mut buff).unwrap();

            let buff: Vec<u8> = buff[0..n].iter_mut().map(|c| char::from(*c).to_ascii_uppercase() as u8).collect();
            stream.write(&buff).unwrap();
        }
    });

    // Connect to the enclave and inspect what it returns
    let mut stream = TcpStream::connect(format!("localhost:{}", parent_port)).expect("Can't connect to runner socket");
    let in_msg = "Hello World!";
    stream.write(in_msg.as_bytes()).unwrap();
    let mut buff = [0u8; 100];
    let n = stream.read(&mut buff).unwrap();
    let out_msg = String::from_utf8((&buff[0..n]).to_vec()).unwrap();
    let mut expected = String::from(in_msg);
    expected.make_ascii_uppercase();
    assert_eq!(expected, out_msg);
}
