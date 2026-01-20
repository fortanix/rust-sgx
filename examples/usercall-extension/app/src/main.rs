use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let mut stream = BufReader::new(TcpStream::connect("cat")?);

    stream.get_mut().write_all(b"Hello, world!\n")?;

    let mut echo = String::new();
    let mut b = BufReader::new(stream);
    b.read_line(&mut echo)?;
    println!("{}", echo);

    let mut stream = BufReader::new(TcpStream::connect("rpc")?);

    stream.get_mut().write_all(b"request")?;
    stream.get_mut().write_all(b"\n")?;

    let mut echo = String::new();
    let mut b = BufReader::new(stream);
    b.read_line(&mut echo)?;
    println!("RPC response: {:?}", echo);

    Ok(())
}
