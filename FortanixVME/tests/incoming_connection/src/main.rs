use std::net::{Shutdown, TcpListener};
use std::io::{Read, Write};

fn main() {
    println!("Bind to socket to 3400");
    let listener = TcpListener::bind("127.0.0.1:3400").expect("Bind failed");
    println!("# Listening on: {}", listener.local_addr().unwrap().port());

    println!("Listening for incoming connections...");
    for id in 1..3 {
        println!("Waiting for connection {}", id);
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                println!("Connection {}: Connected", id);
                let mut buff_in = [0u8; 4192];
                let n = stream.read(&mut buff_in).unwrap();
                println!("# read: {} bytes", n);
                let out = "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\n<html><body>Hello World!</body></html>\r\n";
                stream.write(out.as_bytes());
                stream.shutdown(Shutdown::Both);
            },
            Err(e)              => println!("Connection {}: Accept failed: {:?}", id, e),
        }
    }
}
