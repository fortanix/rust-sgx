use std::io::{BufRead, BufReader};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    for _ in 0..3 {
        let listener = TcpListener::bind("localhost:6010")?;
        let (stream, peer_addr) = listener.accept()?;
        let peer_addr = peer_addr.to_string();
        let local_addr = stream.local_addr()?;
        eprintln!(
            "App:: accept  - local address is {}, peer address is {}",
            local_addr, peer_addr
        );

        let mut reader = BufReader::new(stream);
        let mut message = String::new();
        loop {
            let read_bytes = reader.read_line(&mut message)?;
            if read_bytes == 0 {
                break;
            }
            print!("{}", message);
        }
    }
    Ok(())
}
