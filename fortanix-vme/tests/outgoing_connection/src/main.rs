use std::net::TcpStream;
use std::io::{Read, Write};

fn connect(host: &str, port: u16) {
    let remote = format!("{}:{}", host, port);
    println!("# Running outgoing connection test");
    let mut socket = TcpStream::connect(remote).unwrap();
    // `socket.local_addr()` may return the actual local IP address, not 127.0.0.1
    assert!(socket.local_addr().unwrap().port() != 80);
    assert_eq!(socket.peer_addr().unwrap().port(), port);
    socket.write(b"GET / HTTP/1.1\n\n").unwrap();
    socket.flush().unwrap();
    let mut page = [0; 4192];
    socket.read(&mut page).unwrap();
    let page = String::from_utf8(page.to_vec()).unwrap();

    if page.contains("Google") {
        println!("Connected to Google successfully!");
    } else {
        println!("Failed to read from connection, got: {}", page);
    }
}

fn main() {
    connect("www.google.com", 80);
    connect("127.0.0.1", 3080);
    connect("localhost", 3080);
}
