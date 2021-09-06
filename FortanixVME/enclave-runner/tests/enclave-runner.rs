use fortanix_vme_abi::{self, Response, Request};
use std::thread;
use std::io::{Error as IoError, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const READ_BUFF_SIZE: usize = 10;

fn read_from_stream(stream: &mut TcpStream) -> Result<Vec<u8>, IoError> {
    let mut buff = Vec::new();
    buff.resize(READ_BUFF_SIZE, 0);
    let n = stream.read(&mut buff)?;
    buff.resize(n, 0);
    if n == READ_BUFF_SIZE {
        buff.append(&mut read_from_stream(stream)?);
    }
    Ok(buff)
}

fn read_response(stream: &mut TcpStream) -> Result<Response, IoError> {
    let response = read_from_stream(stream)?;
    Ok(Response::deserialize(&response).unwrap())
}

#[test]
fn test_connect() {
    let _ = thread::spawn(|| {
        let server = enclave_runner::server::Server::new();
        server.run().unwrap();
    });
    thread::sleep(Duration::from_millis(1000));
    let mut runner = TcpStream::connect(format!("localhost:{}", fortanix_vme_abi::SERVER_PORT)).unwrap();
    let connect = Request::Connect {
        addr: "google.com".to_string(),
    };
    let buf = connect.serialize().unwrap();

    runner.write(&buf).unwrap();
    let response = read_response(&mut runner).unwrap();
    println!("response = {:?}", response);
}
