use std::thread;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use fortanix_vme_abi::{self, Error, Response, Request};

pub struct Server {
    port: u16,
}

impl Server {
    pub fn new() -> Self {
        Server {
            port: fortanix_vme_abi::SERVER_PORT,
        }
    }

    fn read_request(stream: &mut TcpStream) -> Result<Request, Error> {
        // Blocks until a full `Request` object is received
        let mut deser = serde_cbor::Deserializer::from_reader(stream).into_iter::<Request>();
        let req = deser
                    .next()
                    .ok_or(Error::ReadFailed)?
                    .map_err(|e| Error::DeserializationError(e))?;
        Ok(req)
    }

    fn handle_client(stream: &mut TcpStream) -> Result<(), IoError> {
        let request = Self::read_request(stream).map_err(|_e| IoError::new(IoErrorKind::InvalidInput, "Failed to read request"))?;
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

