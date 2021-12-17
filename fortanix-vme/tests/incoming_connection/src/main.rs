#![feature(io_error_uncategorized)]
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};

fn server_run() {
    println!("Bind TCP socket to port 3400");
    let listener = TcpListener::bind("127.0.0.1:3400").expect("Bind failed");
    assert_eq!(listener.local_addr().unwrap(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3400));

    let fd = listener.as_raw_fd();
    let listener1 = unsafe { TcpListener::from_raw_fd(fd) };
    assert_eq!(listener1.local_addr().unwrap(), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3400));

    println!("Listening for incoming connections...");
    for id in 1..3 {
        println!("Waiting for connection {}", id);
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("# addr = {:?}", addr);
                assert_eq!(stream.peer_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert!(stream.peer_addr().unwrap().port() != 3400);
                assert_eq!(stream.local_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(stream.local_addr().unwrap().port(), 3400);

                let fd = stream.as_raw_fd();
                let mut stream = unsafe { TcpStream::from_raw_fd(fd) };
                assert_eq!(stream.peer_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert!(stream.peer_addr().unwrap().port() != 3400);
                assert_eq!(stream.local_addr().unwrap().ip(), Ipv4Addr::new(127, 0, 0, 1));
                assert_eq!(stream.local_addr().unwrap().port(), 3400);

                let no_stream = unsafe { TcpStream::from_raw_fd(666.into()) };
                assert_eq!(no_stream.peer_addr().unwrap_err().kind(), ErrorKind::Uncategorized);

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

fn main() {
    for run in 1..=2 {
        println!("Server run #{}", run);
        server_run()
    }
    println!("Bye bye");
}
