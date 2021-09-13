fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests{
    use std::net::TcpStream;
    use std::io::{Read, Write};

    #[test]
    pub fn outbound_connection() {
        let mut socket = TcpStream::connect(format!("google.com:80")).unwrap();
        socket.write(b"GET / HTTP/1.1\n\n").unwrap();
        socket.flush().unwrap();
        let mut page = [0; 4192];
        socket.read(&mut page).unwrap();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("Google"));
    }
}
