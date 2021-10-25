use nix::sys::select::{select, FdSet};
use nix::sys::socket::SockAddr as NixSockAddr;
use serde_cbor;
use std::cmp;
use std::str;
use std::thread::{self, JoinHandle};
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::io::AsRawFd;
use fortanix_vme_abi::{self, Response, Request};
use vsock::{self, Std, VsockListener, VsockStream};

const PROXY_BUFF_SIZE: usize = 4192;

enum Direction {
    Left,
    Right,
}

pub struct Server;

pub trait StreamConnection: Read + Write + AsRawFd + Sized + Send + 'static {
    fn protocol() -> &'static str;

    fn local(&self) -> io::Result<String>;

    fn local_port(&self) -> io::Result<u32>;

    fn peer(&self) -> io::Result<String>;

    fn peer_port(&self) -> io::Result<u32>;
}

impl StreamConnection for TcpStream {
    fn protocol() -> &'static str {
        "tcp"
    }

    fn local(&self) -> io::Result<String> {
        self.local_addr().map(|addr| addr.to_string())
    }

    fn local_port(&self) -> io::Result<u32> {
        self.local_addr().map(|addr| addr.port() as _)
    }

    fn peer(&self) -> io::Result<String> {
        self.peer_addr().map(|addr| addr.to_string())
    }

    fn peer_port(&self) -> io::Result<u32> {
        self.peer_addr().map(|addr| addr.port() as _)
    }
}

impl StreamConnection for VsockStream {
    fn protocol() -> &'static str {
        "vsock"
    }

    fn local(&self) -> io::Result<String> {
        let addr = self.local_addr()?;
        Ok(addr.cid().to_string())
    }

    fn local_port(&self) -> io::Result<u32> {
        let addr = self.local_addr()?;
        Ok(addr.port())
    }

    fn peer(&self) -> io::Result<String> {
        let addr = self.peer_addr()?;
        Ok(addr.cid().to_string())
    }

    fn peer_port(&self) -> io::Result<u32> {
        let addr = self.peer_addr()?;
        Ok(addr.port())
    }
}

impl Server {
    fn log_communication(src: &str, src_port: u32, dst: &str, dst_port: u32, msg: &str, arrow: Direction, prot: &str) {
        let src = format!("{}:{}", src, src_port);
        let dst = format!("{}:{}", dst, dst_port);
        let msg = &msg[0.. cmp::min(msg.len(), 80)];
        let arrow = match arrow {
            Direction::Left => format!("<{:-^width$}", prot, width = 10),
            Direction::Right => format!("{:-^width$}>", prot, width = 10),
        };
        println!("{:>20} {} {:<20}: {:?}", src, arrow, dst, msg);
    }

    fn send(enclave: &mut VsockStream, response: &Response) -> Result<(), IoError> {
        let response: Vec<u8> = serde_cbor::ser::to_vec(response)
                                    .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Serialization failed"))?;
        enclave.write(&response)?;
        Ok(())
    }

    fn read_request(stream: &mut VsockStream) -> Result<Request, IoError> {
        let runner_port = stream.local_port().unwrap_or_default();
        let enclave_port = stream.peer_port().unwrap_or_default();
        let req = serde_cbor::Deserializer::from_reader(stream).into_iter::<Request>()
                    .next() // Blocks until a full `Request` object is received
                    .ok_or(IoError::new(IoErrorKind::Other, "Failed to read request"))?
                    .map_err(|e| IoError::new(IoErrorKind::InvalidInput, e))?;
        Self::log_communication(
            "runner",
            runner_port,
            "enclave",
            enclave_port,
            &format!("{:?}", &req),
            Direction::Left,
            "vsock");
        Ok(req)
    }

    fn transfer_data<S: StreamConnection, D: StreamConnection>(src: &mut S, src_name: &str, dst: &mut D, dst_name: &str) -> Result<usize, IoError> {
        let mut buff = [0; PROXY_BUFF_SIZE];
        let n = src.read(&mut buff[..])?;
        Self::log_communication(
            "runner",
            src.local_port().unwrap_or_default(),
            src_name,
            src.peer_port().unwrap_or_default(),
            &str::from_utf8(&buff[0..n]).unwrap_or_default(),
            Direction::Left,
            S::protocol());
        if n > 0 {
            dst.write_all(&buff[0..n])?;
            Self::log_communication(
                dst_name,
                dst.peer_port().unwrap_or_default(),
                "runner",
                dst.local_port().unwrap_or_default(),
                &str::from_utf8(&buff[0..n]).unwrap_or_default(),
                Direction::Left,
                D::protocol());
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
    fn handle_request_connect(remote_addr: &String, enclave: &mut VsockStream) -> Result<(), IoError> {
        // Connect to remote server
        let mut remote_socket = TcpStream::connect(remote_addr)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let (proxy_server, _proxy_server_cid, proxy_server_port) = Self::bind(0)?;

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
            proxy_port: proxy_server_port,
        };
        Self::log_communication(
            "runner",
            enclave.local_port().unwrap_or_default(),
            "enclave",
            enclave.peer_port().unwrap_or_default(),
            &format!("{:?}", &response),
            Direction::Right,
            "vsock");

        Self::send(enclave, &response)?;

        // Wait for incoming connection from enclave
        let (mut proxy, _proxy_addr) = proxy_server.accept()?;

        // Pass messages between remote server <-> enclave
        loop {
            let mut read_set = FdSet::new();
            read_set.insert(proxy.as_raw_fd());
            read_set.insert(remote_socket.as_raw_fd());

            if let Ok(_num) = select(None, Some(&mut read_set), None, None, None) {
                if read_set.contains(proxy.as_raw_fd()) {
                    if let Err(_) = Self::transfer_data(&mut proxy, "proxy", &mut remote_socket, remote_name) {
                        break;
                    }
                }
                if read_set.contains(remote_socket.as_raw_fd()) {
                    if let Err(_) = Self::transfer_data(&mut remote_socket, remote_name, &mut proxy, "proxy") {
                        break;
                    }
                }
            }
        }
        let _ = proxy.shutdown(Shutdown::Both);
        let _ = remote_socket.shutdown(Shutdown::Both);
        Ok(())
    }

    fn handle_client(stream: &mut VsockStream) -> Result<(), IoError> {
        match Self::read_request(stream) {
            Ok(Request::Connect{ addr }) => Self::handle_request_connect(&addr, stream)?,
            Err(_e)                      => return Err(IoError::new(IoErrorKind::InvalidData, "Failed to read request")),
        };
        Ok(())
    }

    fn bind(port: u32) -> io::Result<(VsockListener, u32, u32)> {
        let listener = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)?;
        let addr = listener.local_addr()?;

        if let NixSockAddr::Vsock(addr) = addr.into() {
            Ok((listener, addr.cid(), addr.port()))
        } else {
            Err(IoError::new(IoErrorKind::InvalidInput, "Unexpected address type"))
        }
    }

    pub fn run(port: u32) -> std::io::Result<(JoinHandle<()>, u32)> {
        println!("Starting enclave runner.");
        let (listener, _cid, port) = Self::bind(port)?;
        println!("Listening on vsock port {}...", port);

        let handle = thread::Builder::new().spawn(move || {
            let listener = listener;
            loop {
                let (stream, _addr) = listener.accept().unwrap();
                let _ = thread::Builder::new()
                    .spawn(move || {
                        let mut stream = stream;
                        if let Err(e) = Self::handle_client(&mut stream) {
                            eprintln!("Error handling connection: {}, shutting connection down", e);
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    });
            }
        })?;
        Ok((handle, port))
    }
}

