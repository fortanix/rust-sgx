use nix::sys::select::{select, FdSet};
use std::thread;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use fortanix_vme_abi::{self, Error, Response, Request};

const BUFF_SIZE: usize = 1024;
const PROXY_BUFF_SIZE: usize = 4192;

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
        let mut buff = [0; BUFF_SIZE];
        let n = stream.read(&mut buff)?;
        let mut buff = buff[0..n].to_vec();
        //TODO This will block when the n*BUFF_SIZE bytes need to be read
        if n == BUFF_SIZE {
            buff.append(&mut Self::read_from_stream(stream)?);
        }
        Ok(buff)
    }

    fn log_communication(src: &str, src_port: u16, dst: &str, dst_port: u16, msg: &str, arrow: &str) {
        let src = format!("{}:{}", src, src_port);
        let dst = format!("{}:{}", dst, dst_port);
        let msg: String = msg.chars().into_iter().take(80).collect();
        println!("{:>20} {} {:<20}: {:?}", src, arrow, dst, msg);
    }

    fn read_request(stream: &mut TcpStream) -> Result<Request, Error> {
        let buff = Self::read_from_stream(stream)?;
        let req = serde_cbor::from_slice(&buff).map_err(|e| Error::DeserializationError(e))?;
        Self::log_communication(
            "runner",
            stream.local_addr().map(|addr| addr.port()).unwrap_or_default(),
            "enclave",
            stream.peer_addr().map(|addr| addr.port()).unwrap_or_default(),
            &format!("{:?}", &req),
            "<-");
        Ok(req)
    }

    fn transfer_data(src: &mut TcpStream, src_name: &str, dst: &mut TcpStream, dst_name: &str) -> Result<usize, IoError> {
        let mut buff = [0; PROXY_BUFF_SIZE];
        let n = src.read(&mut buff[..])?;
        Self::log_communication(
            "runner",
            src.local_addr().map(|addr| addr.port()).unwrap_or_default(),
            src_name,
            src.peer_addr().map(|addr| addr.port()).unwrap_or_default(),
            &String::from_utf8(buff[0..n].to_vec()).unwrap_or_default(),
            "<-");
        if n > 0 {
            dst.write_all(&buff[0..n])?;
            Self::log_communication(
                dst_name,
                dst.peer_addr().map(|addr| addr.port()).unwrap_or_default(),
                "runner",
                dst.local_addr().map(|addr| addr.port()).unwrap_or_default(),
                &String::from_utf8(buff[0..n].to_vec()).unwrap_or_default(),
                "<-");
        }
        Ok(n)
    }

    /*
     * +-----------+
     * |   remote  |
     * +-----------+
     *       ^
     *       |
     *       |
     *       v
     * +----[2]-----+            +-------------+
     * |   Runner   |            |   enclave   |
     * +--[3]--[1]--+            +-[ ]----[ ]--+
     *     \    \---- enclave ------/      /
     *      \-------- proxy --------------/
     *
     *  [1] enclave
     *  [2] remote
     *  [3] proxy
     */
    fn handle_request_connect(remote_addr: &String, enclave: &mut TcpStream) -> Result<(), IoError> {
        // Connect to remote server
        let mut remote_socket = TcpStream::connect(remote_addr)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let proxy_server = TcpListener::bind("127.0.0.1:0")?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
                port: proxy_server_port,
                local_addr: enclave.local_addr()?.to_string(),
                peer_addr: enclave.peer_addr()?.to_string(),
            };
        Self::log_communication(
            "runner",
            enclave.local_addr().map(|addr| addr.port()).unwrap_or_default(),
            "enclave",
            enclave.peer_addr().map(|addr| addr.port()).unwrap_or_default(),
            &format!("{:?}", &response),
            "->");
        enclave.write(&serde_cbor::ser::to_vec(&response).unwrap())?;

        // Wait for incoming connection from enclave
        let mut proxy = proxy_server.incoming().next().unwrap()?;

        // Pass messages between remote server <-> enclave
        loop {
            let mut fd_set = FdSet::new();
            fd_set.insert(proxy.as_raw_fd());
            fd_set.insert(remote_socket.as_raw_fd());
            select(None, Some(&mut fd_set), None, None, None).unwrap();

            if fd_set.contains(proxy.as_raw_fd()) {
                if Self::transfer_data(&mut proxy, "proxy", &mut remote_socket, remote_name).is_err() {
                    break;
                }
            }
            if fd_set.contains(remote_socket.as_raw_fd()) {
                if Self::transfer_data(&mut remote_socket, remote_name, &mut proxy, "proxy").is_err() {
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_client(stream: &mut TcpStream) -> Result<(), IoError> {
        match Self::read_request(stream) {
            Ok(Request::Connect{ addr }) => Self::handle_request_connect(&addr, stream)?,
            Err(_e)                      => return Err(IoError::new(IoErrorKind::InvalidInput, "Failed to read request")),
        };
        Ok(())
    }

    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))?;

        for stream in listener.incoming() {
            let mut stream = stream?;
            thread::Builder::new()
                .spawn(move || {
                    if let Err(e) = Self::handle_client(&mut stream) {
                        eprintln!("Error handling connection: {}, shutting connection down", e);
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                })?;
        }
        Ok(())
    }
}

