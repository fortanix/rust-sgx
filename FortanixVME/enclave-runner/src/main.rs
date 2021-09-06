use std::thread;
use std::io::{Error as IoError, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use fortanix_vme_abi;

const READ_BUFF_SIZE: usize = 10;

fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, IoError> {
    let mut buff = Vec::new();
    buff.resize(READ_BUFF_SIZE, 0);
    let n = stream.read(&mut buff)?;
    if n == READ_BUFF_SIZE {
        buff.append(&mut read_request(stream)?);
    }
    Ok(buff)
}

fn handle_client(stream: &mut TcpStream) -> Result<(), IoError> {
    let request = read_request(stream)?;
    let s = String::from_utf8(request).unwrap_or_default();

    println!("Received: {}", s);
    stream.write(b"Hello from runner!")?;

    Ok(())
}

fn run_server() -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", fortanix_vme_abi::SERVER_PORT))?;

    for stream in listener.incoming() {
        let result = stream
            .map_err(|e| format!("Failed to connect to client: {}", e))
            .map(|mut stream| thread::Builder::new()
                .spawn(move || {
                    if let Err(e) = handle_client(&mut stream) {
                        eprintln!("Error handling connection: {}, shutting connection down", e);
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }).map_err(|_| "Launch failed"));

        if let Err(e) = result {
            eprintln!("Error: {}", e);
        }
    }
    Ok(())
}

fn main() {
    run_server().expect("Server failed");
}
