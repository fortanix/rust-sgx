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
use std::sync::{Arc, Mutex, RwLock};
use fortanix_vme_abi::{self, Addr, Response, Request};
use vsock::{self, SockAddr as VsockAddr, Std, Vsock, VsockListener, VsockStream};

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

struct Listener {
    listener: TcpListener,
}

impl Listener {
    fn new(listener: TcpListener) -> Self {
        Listener{ listener }
    }
}

#[derive(Debug)]
struct Connection {
    tcp_stream: TcpStream,
    vsock_stream: VsockStream<Std>,
    remote_name: String,
}

impl Connection {
    fn new(vsock_stream: VsockStream<Std>, tcp_stream: TcpStream, remote_name: String) -> Self {
        Connection {
            tcp_stream,
            vsock_stream,
            remote_name,
        }
    }

    fn close(&self) {
        let _ = self.tcp_stream.shutdown(Shutdown::Both);
        let _ = self.vsock_stream.shutdown(Shutdown::Both);
    }

    /// Exchanges messages between the remote server and enclave. Returns `true` when the
    /// connection should remain active, false otherwise
    fn proxy(&mut self) -> bool {
        fn exchange<S: StreamConnection, D: StreamConnection>(src: &mut S, src_name: &str, dst: &mut D, dst_name: &str) -> bool {
            // According to the `Read` threat documentation, reading 0 bytes
            // indicates that the connection has been shutdown correctly. So we
            // close the proxy service
            // https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
            match Server::transfer_data(src, src_name, dst, dst_name) {
                Ok(n) if n == 0 => false,
                Ok(_)           => true,
                Err(_)          => false,
            }
        }
        let remote = self.tcp_stream.as_raw_fd();
        let proxy = self.vsock_stream.as_raw_fd();

        let mut read_set = FdSet::new();
        read_set.insert(remote);
        read_set.insert(proxy);

        if let Ok(_num) = select(None, Some(&mut read_set), None, None, None) {
            if read_set.contains(remote) {
                return exchange(&mut self.tcp_stream, &self.remote_name, &mut self.vsock_stream, "proxy");
            }
            if read_set.contains(proxy) {
                return exchange(&mut self.vsock_stream, "proxy", &mut self.tcp_stream, &self.remote_name);
            }
        }
        true
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    enclave: VsockAddr,
    runner: VsockAddr,
}

impl ConnectionKey {
    fn from_vsock_stream(runner_enclave: &VsockStream<Std>) -> Self {
        let runner_cid = runner_enclave.local_addr().unwrap().cid();
        let runner_port = runner_enclave.local_addr().unwrap().port();
        let enclave_cid = runner_enclave.peer_addr().unwrap().cid();
        let enclave_port = runner_enclave.peer_addr().unwrap().port();
        Self::connection_key(enclave_cid, enclave_port, runner_cid, runner_port)
    }

    fn from_addresses(enclave: VsockAddr, runner: VsockAddr) -> Self {
        ConnectionKey {
            enclave,
            runner,
        }
    }

    fn connection_key(enclave_cid: u32, enclave_port: u32, runner_cid: u32, runner_port: u32) -> Self {
        let enclave = VsockAddr::new(enclave_cid, enclave_port);
        let runner = VsockAddr::new(runner_cid, runner_port);
        Self::from_addresses(enclave, runner)
    }
}

pub struct Server {
    command_listener: Mutex<VsockListener>,
    /// Tracks information about TCP sockets that are currently listening for new connections. For
    /// every TCP listener socket in the runner, there is a vsock listener socket in the enclave.
    /// When the enclave instructs to accept a new connection, the runner accepts a new TCP
    /// connection. It then locates the ListenerInfo and finds the information it needs to set up a
    /// new vsock connection to the enclave
    listeners: RwLock<FnvHashMap<VsockAddr, Arc<Mutex<Listener>>>>,
    connections: RwLock<FnvHashMap<ConnectionKey, Arc<Mutex<Connection>>>>,
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
    fn handle_request_connect(server: Arc<Self>, remote_addr: &String, enclave: &mut VsockStream) -> Result<(), IoError> {
        // Connect to remote server
        let remote_socket = TcpStream::connect(remote_addr)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let proxy_server = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, 0)?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
            proxy_port: proxy_server_port,
            local: remote_socket.local_addr()?.into(),
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
        let (proxy, _proxy_addr) = proxy_server.accept()?;

        // Store connection info
        server.add_connection(proxy, remote_socket, remote_name.to_string());

        Ok(())
    }

    fn add_listener(&self, addr: VsockAddr, info: Listener) {
        self.listeners.write().unwrap().insert(addr, Arc::new(Mutex::new(info)));
    }

    fn listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.read().unwrap().get(&addr).cloned()
    }

    // Preliminary work for PLAT-367
    #[allow(dead_code)]
    fn connection(&self, enclave: VsockAddr, runner: VsockAddr) -> Option<Arc<Mutex<Connection>>> {
        let k = ConnectionKey::from_addresses(enclave, runner);
        self.connections
            .read()
            .unwrap()
            .get(&k)
            .cloned()
    }

    fn add_connection(&self, runner_enclave: VsockStream<Std>, runner_remote: TcpStream, remote_name: String) {
        let k = ConnectionKey::from_vsock_stream(&runner_enclave);
        let info = Connection::new(runner_enclave, runner_remote, remote_name);
        self.connections.write().unwrap().insert(k.clone(), Arc::new(Mutex::new(info)));
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
    fn handle_request_bind(server: Arc<Self>, addr: &String, enclave_port: u32, enclave: &mut VsockStream) -> Result<(), IoError> {
        let cid: u32 = enclave.peer().unwrap().parse().unwrap_or(vsock::VMADDR_CID_HYPERVISOR);
        let listener = TcpListener::bind(addr)?;
        let local: Addr = listener.local_addr()?.into();
        server.add_listener(VsockAddr::new(cid, enclave_port), Listener::new(listener));
        let response = Response::Bound{ local };
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

    fn handle_request_accept(server: Arc<Self>, vsock_listener_port: u32, enclave: &mut VsockStream) -> Result<(), IoError> {
        let enclave_cid: u32 = enclave.peer().unwrap().parse().unwrap_or(vsock::VMADDR_CID_HYPERVISOR);
        let enclave_addr = VsockAddr::new(enclave_cid, vsock_listener_port);
        let listener = server.listener(&enclave_addr)
            .ok_or(IoError::new(IoErrorKind::InvalidInput, "Information about provided file descriptor was not found"))?;
        let listener = listener.lock().unwrap();

        match listener.listener.accept() {
            Ok((conn, peer)) => {
                let vsock = Vsock::new::<Std>()?;
                let runner_addr = vsock.addr::<Std>()?;
                let response = Response::IncomingConnection{
                    local: conn.local_addr()?.into(),
                    peer: peer.into(),
                    proxy_port: runner_addr.port(),
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

                let proxy = vsock.connect_with_cid_port(enclave_addr.cid(), enclave_addr.port()).unwrap();
                server.add_connection(proxy, conn, "remote".to_string());

                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    fn proxy_connections(server: Arc<Server>) {
        let mut closed_connections = Vec::new();

        loop {
            // Exchange messages on every proxy connection
            // TODO: Store connections as a linked hash map so we don't need to keep a read lock
            // over the HashMap while every connection is serviced
            if let Ok(connections) = server.connections.read() {
                for (key, connection) in connections.iter() {
                    match connection.try_lock() {
                        Ok(mut connection) => if !connection.proxy() {
                                            connection.close();
                                            closed_connections.push(key.clone());
                                          }
                        Err(_) => (),
                    }
                }
            }

            // Remove closed connections
            let mut num_connections = None;
            if let Ok(mut connections) = server.connections.try_write() {
                while let Some(k) = closed_connections.pop() {
                    connections.remove(&k);
                }
                num_connections = Some(connections.len());
            }

            if num_connections == Some(0) {
                thread::yield_now();
            }
        }
    }

    fn handle_client(server: Arc<Self>, stream: &mut VsockStream) -> Result<(), IoError> {
        match Self::read_request(stream) {
            Ok(Request::Connect{ addr })             => Self::handle_request_connect(server, &addr, stream)?,
            Ok(Request::Bind{ addr, enclave_port })  => Self::handle_request_bind(server, &addr, enclave_port, stream)?,
            Ok(Request::Accept{ enclave_port })      => Self::handle_request_accept(server, enclave_port, stream)?,
            Err(_e)                                  => return Err(IoError::new(IoErrorKind::InvalidData, "Failed to read request")),
        };
        Ok(())
    }

    fn bind(port: u32) -> io::Result<Server> {
        let command_listener = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)?;
        Ok(Server {
            command_listener: Mutex::new(command_listener),
            listeners: RwLock::new(FnvHashMap::default()),
            connections: RwLock::new(FnvHashMap::default()),
        })
    }

    fn start_proxy_server(server: Arc<Server>) -> Result<JoinHandle<()>, IoError> {
        thread::Builder::new()
            .spawn(move || {
                Self::proxy_connections(server);
            })
    }

    fn start_command_server(server: Arc<Server>) -> Result<JoinHandle<()>, IoError> {
        thread::Builder::new().spawn(move || {
            let command_listener = server.command_listener.lock().unwrap();
            for stream in command_listener.incoming() {
            let server = server.clone();
            let _ = thread::Builder::new()
                .spawn(move || {
                    let mut stream = stream.unwrap();
                    if let Err(e) = Self::handle_client(server, &mut stream) {
                        eprintln!("Error handling connection: {}, shutting connection down", e);
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                });
            }
        })
    }

    pub fn run(port: u32) -> std::io::Result<JoinHandle<()>> {
        println!("Starting enclave runner.");
        let server = Arc::new(Self::bind(port)?);
        let port = server.command_listener.lock().unwrap().local_addr()?.port();
        println!("Listening on vsock port {}...", port);

        Server::start_proxy_server(server.clone())?;
        let handle = Server::start_command_server(server.clone())?;

        Ok(handle)
    }
}

