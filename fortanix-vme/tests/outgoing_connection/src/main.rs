use std::net::{Ipv4Addr, TcpStream};
use std::io::{Read, Write};

fn main() {
    let mut socket = TcpStream::connect(format!("google.com:80")).unwrap();
    // `socket.local_addr()` may return the actual local IP address, not 127.0.0.1
    assert!(socket.local_addr().unwrap().port() != 80);
    assert!(socket.peer_addr().unwrap().ip() != Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(socket.peer_addr().unwrap().port(), 80);
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
