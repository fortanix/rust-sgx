use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener};
use std::io::{Read, Write};

fn main() {
    println!("Bind to socket to 3400");
    let listener = TcpListener::bind("127.0.0.1:3400").expect("Bind failed");
    assert_eq!(listener.local_addr().unwrap(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3400));

    println!("Listening for incoming connections...");
    for id in 1..3 {
        println!("Waiting for connection {}", id);
        match listener.accept() {
            Ok((mut stream, addr)) => {
                println!("# addr = {:?}", addr);
                assert_eq!(stream.peer_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert!(stream.peer_addr().unwrap().port() != 3400);
                assert_eq!(stream.local_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(stream.local_addr().unwrap().port(), 3400);
                println!("Connection {}: Connected", id);
                let mut buff_in = [0u8; 4192];
                let n = stream.read(&mut buff_in).unwrap();
                println!("# read: {} bytes", n);
                let out = "HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\n<html><body>Hello World!</body></html>\r\n";
                stream.write(out.as_bytes()).unwrap();
                stream.shutdown(Shutdown::Both).unwrap();
            },
            Err(e)              => println!("Connection {}: Accept failed: {:?}", id, e),
        }
    }
}
