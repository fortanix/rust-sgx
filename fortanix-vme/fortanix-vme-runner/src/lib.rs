#![deny(warnings)]
use fnv::FnvHashMap;
use nix::sys::select::{select, FdSet};
use serde_cbor;
use std::cmp;
use std::str;
use std::thread::{self, JoinHandle};
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::sync::{Arc, Mutex};
use fortanix_vme_abi::{self, Response, Request};
use vsock::{self, Std, Vsock, VsockListener, VsockStream};

const PROXY_BUFF_SIZE: usize = 4192;

enum Direction {
    Left,
    Right,
}

pub trait StreamConnection: Read + Write {
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

struct ListenerInfo {
    listener: TcpListener,
    enclave_cid: u32,
    enclave_port: u32,
}

pub struct Server {
    command_listener: Mutex<VsockListener>,
    /// Tracks information about TCP sockets that are currently listening for new connections. For
    /// every TCP listener socket in the runner, there is a vsock listener socket in the enclave.
    /// When the enclave instructs to accept a new connection, the runner accepts a new TCP
    /// connection. It then locates the ListenerInfo and finds the information it needs to set up a
    /// new vsock connection to the enclave
    listeners: Mutex<FnvHashMap<RawFd, Arc<Mutex<ListenerInfo>>>>,
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
        if n > 0 {
            Self::log_communication(
                "runner",
                src.local_port().unwrap_or_default(),
                src_name,
                src.peer_port().unwrap_or_default(),
                &str::from_utf8(&buff[0..n]).unwrap_or_default(),
                Direction::Left,
                S::protocol());
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
    fn handle_request_connect(&self, remote_addr: &String, enclave: &mut VsockStream) -> Result<(), IoError> {
        // Connect to remote server
        let mut remote_socket = TcpStream::connect(remote_addr)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let proxy_server = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, 0)?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
            proxy_port: proxy_server_port,
            peer: remote_socket.peer_addr()?.into(),
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
        Self::proxy_connection((&mut remote_socket, remote_name), (&mut proxy, "proxy"));
        Ok(())
    }

    fn add_listener_info(&self, info: ListenerInfo) -> RawFd {
        let fd = info.listener.as_raw_fd();
        self.listeners.lock().unwrap().insert(fd, Arc::new(Mutex::new(info)));
        fd
    }

    fn listener_info(&self, fd: &RawFd) -> Option<Arc<Mutex<ListenerInfo>>> {
        self.listeners.lock().unwrap().get(&fd).cloned()
    }

    /*
     * +-----------+
     * |   remote  |
     * +-----------+
     *       ^
     *       |
     *      TCP
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
     *  `addr`: The address to bind the TCP connection on
     *  `enclave_port`: The vsock port the enclave is listening on for new connections from the
     *  runner
     *  `enclave`: The runner-enclave vsock connection
     */
    fn handle_request_bind(&self, addr: &String, enclave_port: u32, enclave: &mut VsockStream) -> Result<(), IoError> {
        let cid: u32 = enclave.peer().unwrap().parse().unwrap_or(vsock::VMADDR_CID_HYPERVISOR);
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?.into();
        let fd = self.add_listener_info(ListenerInfo{ listener, enclave_cid: cid, enclave_port });
        let response = Response::Bound{ local, fd };
        Self::log_communication(
            "runner",
            enclave.local_port().unwrap_or_default(),
            "enclave",
            enclave.peer_port().unwrap_or_default(),
            &format!("{:?}", &response),
            Direction::Right,
            "vsock");
        enclave.write(&serde_cbor::ser::to_vec(&response).unwrap())?;
        Ok(())
    }

    fn handle_request_accept(&self, fd: RawFd, enclave: &mut VsockStream) -> Result<(), IoError> {
        let listener_info = self.listener_info(&fd)
            .ok_or(IoError::new(IoErrorKind::InvalidInput, "Information about provided file descriptor was not found"))?;
        let listener_info = listener_info.lock().unwrap();
        let (cid, port) = (listener_info.enclave_cid, listener_info.enclave_port);
        match listener_info.listener.accept() {
            Ok((mut conn, peer)) => {
                let vsock = Vsock::new::<Std>()?;
                let response = Response::IncomingConnection{
                    peer: peer.into(),
                    proxy_port: vsock.addr::<Std>()?.port(),
                };
                Self::log_communication(
                    "runner",
                    enclave.local_port().unwrap_or_default(),
                    "enclave",
                    enclave.peer_port().unwrap_or_default(),
                    &format!("{:?}", &response),
                    Direction::Right,
                    "vsock");
                enclave.write(&serde_cbor::ser::to_vec(&response).unwrap())?;
                let _ = thread::Builder::new().spawn(move || {
                    let mut proxy = vsock.connect_with_cid_port(cid, port).unwrap();
                    Self::proxy_connection((&mut conn, "remote"), (&mut proxy, "proxy"));
                });
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn proxy_connection(remote: (&mut TcpStream, &str), proxy: (&mut VsockStream, &str)) {
        loop {
            let mut read_set = FdSet::new();
            read_set.insert(remote.0.as_raw_fd());
            read_set.insert(proxy.0.as_raw_fd());

            if let Ok(_num) = select(None, Some(&mut read_set), None, None, None) {
                if read_set.contains(remote.0.as_raw_fd()) {
                    match Self::transfer_data(remote.0, remote.1, proxy.0, proxy.1) {
                        Ok(0)  => {
                            // According to the `Read` threat documentation, reading 0 bytes
                            // indicates that the connection has been shutdown correctly. So we
                            // close the proxy service
                            // https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
                            break
                        },
                        Ok(_)  => (),
                        Err(e) => {
                            eprintln!("transfer from remote failed: {:?}", e);
                            break;
                        }
                    }
                }
                if read_set.contains(proxy.0.as_raw_fd()) {
                    match Self::transfer_data(proxy.0, proxy.1, remote.0, remote.1) {
                        Ok(0)  => break,
                        Ok(_)  => (),
                        Err(e) => {
                            eprintln!("transfer from proxy failed: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }
        let _ = proxy.0.shutdown(Shutdown::Both);
        let _ = remote.0.shutdown(Shutdown::Both);
    }

    fn handle_client(&self, stream: &mut VsockStream) -> Result<(), IoError> {
        match Self::read_request(stream) {
            Ok(Request::Connect{ addr })             => self.handle_request_connect(&addr, stream)?,
            Ok(Request::Bind{ addr, enclave_port })  => self.handle_request_bind(&addr, enclave_port, stream)?,
            Ok(Request::Accept{ fd })                => self.handle_request_accept(fd, stream)?,
            Err(_e)                                  => return Err(IoError::new(IoErrorKind::InvalidData, "Failed to read request")),
        };
        Ok(())
    }

    fn bind(port: u32) -> io::Result<Server> {
        let command_listener = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)?;
        Ok(Server {
            command_listener: Mutex::new(command_listener),
            listeners: Mutex::new(FnvHashMap::default()),
        })
    }

    pub fn run(port: u32) -> std::io::Result<(JoinHandle<()>, u32)> {
        println!("Starting enclave runner.");
        let server = Arc::new(Self::bind(port)?);
        let port = server.command_listener.lock().unwrap().local_addr()?.port();
        println!("Listening on vsock port {}...", port);

        let handle = thread::Builder::new().spawn(move || {
            let server = server;
            let server = server.clone();
            let command_listener = server.command_listener.lock().unwrap();
            for stream in command_listener.incoming() {
                let server = server.clone();
                let _ = thread::Builder::new()
                    .spawn(move || {
                        let mut stream = stream.unwrap();
                        if let Err(e) = server.handle_client(&mut stream) {
                            eprintln!("Error handling connection: {}, shutting connection down", e);
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    });
            }
        })?;
        Ok((handle, port))
    }
}

