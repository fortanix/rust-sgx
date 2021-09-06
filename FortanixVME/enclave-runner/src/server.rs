use std::thread;
use std::io::{Error as IoError, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use fortanix_vme_abi::{self, Response, Request};

const READ_BUFF_SIZE: usize = 10;

pub struct Server {
    port: u16,
}

impl Server {
    pub fn new() -> Self {
        Server {
            port: fortanix_vme_abi::SERVER_PORT,
        }
    }

    fn read_from_stream(stream: &mut TcpStream) -> Result<Vec<u8>, IoError> {
        let mut buff = Vec::new();
        buff.resize(READ_BUFF_SIZE, 0);
        let n = stream.read(&mut buff)?;
        buff.resize(n, 0);
        println!("read: {:?} ({}bytes)", buff, n);
        if n == READ_BUFF_SIZE {
            buff.append(&mut Self::read_from_stream(stream)?);
        }
        Ok(buff)
    }

    fn read_request(stream: &mut TcpStream) -> Result<Request, IoError> {
        let buff = Self::read_from_stream(stream)?;
        Ok(Request::deserialize(&buff).unwrap())
    }

    fn handle_client(stream: &mut TcpStream) -> Result<(), IoError> {
        let request = Self::read_request(stream)?;
        let response = match request {
            Request::Connect{ addr } => {
                println!("Received connect request to : {:?}", addr);
                Response::Connected {
                    port: 42,
                    local_addr: "local".to_string(),
                    peer_addr: "peer".to_string()
                }
            },
        };
        stream.write(&response.serialize().unwrap())?;
        Ok(())
    }

    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))?;

        for stream in listener.incoming() {
            let result = stream
                .map_err(|e| format!("Failed to connect to client: {}", e))
                .map(|mut stream| thread::Builder::new()
                    .spawn(move || {
                        if let Err(e) = Self::handle_client(&mut stream) {
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
}

