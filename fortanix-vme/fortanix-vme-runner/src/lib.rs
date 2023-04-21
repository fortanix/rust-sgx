#![deny(warnings)]
use fnv::FnvHashMap;
use nix::sys::select::{select, FdSet};
use log::{error, info, log, warn};
use serde_cbor::{self, StreamDeserializer};
use serde_cbor::de::IoRead;
use std::cmp;
use std::str;
use std::thread::{self, JoinHandle};
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::marker::PhantomData;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, RwLock};
use fortanix_vme_abi::{self, Addr, Error as VmeError, Response, Request, SERVER_PORT};
use vsock::{self, SockAddr as VsockAddr, Std, Vsock, VsockListener, VsockStream};

mod platforms;
pub use platforms::{Platform, NitroEnclaves, Simulator, SimulatorArgs};

const MAX_LOG_MESSAGE_LEN: usize = 80;
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

#[derive(Clone, Debug)]
struct ConnectionInfo {
    /// The local address (as used by the runner)
    local: Addr,
    /// The address of the remote party for open connection, None for server sockets
    peer: Addr,
}

impl Connection {
    pub fn new(vsock_stream: VsockStream<Std>, tcp_stream: TcpStream, remote_name: String) -> Self {
        Connection {
            tcp_stream,
            vsock_stream,
            remote_name,
        }
    }

    pub fn info(&self) -> Result<ConnectionInfo, IoError> {
        Ok(ConnectionInfo {
            local: self.tcp_stream.local_addr()?.into(),
            peer: self.tcp_stream.peer_addr()?.into(),
        })
    }

    fn transfer_data<S: StreamConnection, D: StreamConnection>(src: &mut S, src_name: &str, dst: &mut D, dst_name: &str) -> Result<usize, IoError> {
        let mut buff = [0; PROXY_BUFF_SIZE];
        let n = src.read(&mut buff[..])?;
        if n > 0 {
            ClientConnection::log_communication(
                log::Level::Debug,
                "runner",
                src.local_port().unwrap_or_default(),
                src_name,
                src.peer_port().unwrap_or_default(),
                &str::from_utf8(&buff[0..n]).unwrap_or_default(),
                Direction::Left,
                S::protocol(),
                Some(MAX_LOG_MESSAGE_LEN));
            dst.write_all(&buff[0..n])?;
            ClientConnection::log_communication(
                log::Level::Debug,
                dst_name,
                dst.peer_port().unwrap_or_default(),
                "runner",
                dst.local_port().unwrap_or_default(),
                &str::from_utf8(&buff[0..n]).unwrap_or_default(),
                Direction::Left,
                D::protocol(),
                Some(MAX_LOG_MESSAGE_LEN));
        }
        Ok(n)
    }

    /// Exchanges messages between the remote server and enclave. Returns on error, or when one of
    /// the connections terminated
    pub fn proxy(&mut self) -> Result<(), IoError> {
        let remote = &mut self.tcp_stream;
        let enclave = &mut self.vsock_stream;

        let mut golden_set = FdSet::new();
        golden_set.insert(remote.as_raw_fd());
        golden_set.insert(enclave.as_raw_fd());

        while golden_set != FdSet::new() {
            let mut read_set = golden_set.clone();

            if let Ok(_num) = select(None, Some(&mut read_set), None, None, None) {
                if read_set.contains(remote.as_raw_fd()) {
                    // According to the `Read` trait documentation, reading 0 bytes
                    // indicates that the connection has been shutdown (for writes) correctly. We
                    //  - reflect this change on the other connection
                    //  - avoid reading from the socket again
                    // https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read
                    if Self::transfer_data(remote, &self.remote_name, enclave, "enclave")? == 0 {
                        enclave.shutdown(Shutdown::Write)?;
                        golden_set.remove(remote.as_raw_fd());
                    }
                }
                if read_set.contains(enclave.as_raw_fd()) {
                    if Self::transfer_data(enclave, "enclave", remote, &self.remote_name)? == 0 {
                        remote.shutdown(Shutdown::Write)?;
                        golden_set.remove(enclave.as_raw_fd());
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    enclave: VsockAddr,
    runner: VsockAddr,
}

impl ConnectionKey {
    pub fn from_vsock_stream(runner_enclave: &VsockStream<Std>) -> Result<Self, IoError> {
        let runner_cid = runner_enclave.local_addr()?.cid();
        let runner_port = runner_enclave.local_addr()?.port();
        let enclave_cid = runner_enclave.peer_addr()?.cid();
        let enclave_port = runner_enclave.peer_addr()?.port();
        Ok(Self::connection_key(enclave_cid, enclave_port, runner_cid, runner_port))
    }

    pub fn from_addresses(enclave: VsockAddr, runner: VsockAddr) -> Self {
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

pub struct ClientConnection<'de> {
    sender: VsockStream,
    reader: StreamDeserializer<'de, IoRead<VsockStream>, Request>,
}

impl<'de> ClientConnection<'de> {
    pub fn new(stream: VsockStream) -> Self {
        // Mimic splitting the stream in a read and send part
        let sender = unsafe { VsockStream::from_raw_fd(stream.as_raw_fd()) };
        ClientConnection {
            sender,
            reader: serde_cbor::Deserializer::from_reader(stream).into_iter::<Request>(),
        }
    }

    pub fn peer_port(&self) -> Result<u32, IoError> {
        self.sender.peer()?.parse().map_err(|e| IoError::new(IoErrorKind::InvalidData, e))
    }

    fn log_communication(level: log::Level, src: &str, src_port: u32, dst: &str, dst_port: u32, msg: &str, arrow: Direction, prot: &str, max_len: Option<usize>) {
        let src = format!("{}:{}", src, src_port);
        let dst = format!("{}:{}", dst, dst_port);
        let msg = if let Some(max) = max_len {
            &msg[0.. cmp::min(msg.len(), max)]
        } else {
            &msg[..]
        };
        let arrow = match arrow {
            Direction::Left => format!("<{:-^width$}", prot, width = 10),
            Direction::Right => format!("{:-^width$}>", prot, width = 10),
        };
        log!(level, "{:>20} {} {:<20}: {:?}", src, arrow, dst, msg);
    }

    pub fn send(&mut self, response: &Response) -> Result<(), IoError> {
        Self::log_communication(
            log::Level::Info,
            "runner",
            self.sender.local_port().unwrap_or_default(),
            "enclave",
            self.sender.peer_port().unwrap_or_default(),
            &format!("{:?}", response),
            Direction::Right,
            "vsock",
            None);
        let response: Vec<u8> = serde_cbor::ser::to_vec(response)
                                    .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Serialization failed"))?;
        self.sender.write(&response)?;
        Ok(())
    }

    pub fn read_request(&mut self) -> Result<Request, IoError> {
        let req = self.reader.next() // Blocks until a full `Request` object is received
                    .ok_or(IoError::new(IoErrorKind::Other, "Failed to read request"))?
                    .map_err(|e| IoError::new(IoErrorKind::InvalidInput, e))?;
        Self::log_communication(
            log::Level::Info,
            "runner",
            self.sender.local_port().unwrap_or_default(),
            "enclave",
            self.sender.peer_port().unwrap_or_default(),
            &format!("{:?}", &req),
            Direction::Left,
            "vsock",
            None);
        Ok(req)
    }
}

pub struct EnclaveRunner<P: Platform> {
    servers: Vec<(Arc<Server<P>>, JoinHandle<()>)>,
    platform: PhantomData<P>,
}

impl<P: Platform + 'static> EnclaveRunner<P> {
    /// Creates a new enclave runner
    pub fn new() -> Result<EnclaveRunner<P>, IoError> {
        Ok(EnclaveRunner {
            servers: Vec::new(),
            platform: PhantomData,
        })
    }

    /// Starts a new enclave
    pub fn run_enclave<I: Into<P::RunArgs>>(&mut self, run_args: I, enclave_args: Vec<String>) -> Result<(), VmeError> {
        let server = Arc::new(Server::bind(SERVER_PORT)?);
        let server_thread = server.clone().run_command_server()?;
        server.run_enclave(run_args, enclave_args)?;
        self.servers.push((server, server_thread));
        Ok(())
    }

    /// Blocks the current thread until the command thread exits
    pub fn wait(self) {
        self.servers
            .into_iter()
            .for_each(|(_, thread)| { let _ = thread.join(); });
    }
}

#[allow(dead_code)]
enum EnclaveState<P: Platform> {
    Null,
    Running {
        enclave: P::EnclaveDescriptor,
        args: Vec<String>,
    },
}

pub struct Server<P: Platform> {
    enclave: RwLock<EnclaveState<P>>,
    command_listener: Mutex<VsockListener>,
    /// Tracks information about TCP sockets that are currently listening for new connections. For
    /// every TCP listener socket in the runner, there is a vsock listener socket in the enclave.
    /// When the enclave instructs to accept a new connection, the runner accepts a new TCP
    /// connection. It then locates the ListenerInfo and finds the information it needs to set up a
    /// new vsock connection to the enclave
    listeners: RwLock<FnvHashMap<VsockAddr, Arc<Mutex<Listener>>>>,
    connections: RwLock<FnvHashMap<ConnectionKey, ConnectionInfo>>,
}

impl<P: Platform + 'static> Server<P> {
    fn handle_request_init(self: Arc<Self>, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let state = self.enclave.read().unwrap();
        let args = match &*state {
            EnclaveState::Null => panic!("Not yet running enclave requesting initialization"),
            EnclaveState::Running { args, .. } => args.to_owned(),
        };
        let response = Response::Init {
            args,
        };
        conn.send(&response)?;
        Ok(())
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
    fn handle_request_connect(self: Arc<Self>, remote_addr: &String, conn: &mut ClientConnection) -> Result<(), VmeError> {
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

        conn.send(&response)?;

        // Wait for incoming connection from enclave. Unfortunately, we can't send a second
        // response with an error message back to the enclave when something goes wrong anymore.
        // We'll log the problem instead
        let accept_connection = move || -> Result<(), VmeError> {
            let (proxy, _proxy_addr) = proxy_server.accept()?;
            // Store connection info
            self.add_connection(proxy, remote_socket, remote_name.to_string())?;
            Ok(())
        };
        if let Err(e) = accept_connection() {
            error!("Failed to accept connection from the enclave: {:?}", e);
        }
        Ok(())
    }

    fn add_listener(&self, addr: VsockAddr, info: Listener) {
        self.listeners.write().unwrap().insert(addr, Arc::new(Mutex::new(info)));
    }

    fn listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.read().unwrap().get(&addr).cloned()
    }

    fn remove_listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.write().unwrap().remove(&addr)
    }

    fn connection_info(&self, enclave: VsockAddr, runner_port: u32) -> Option<ConnectionInfo> {
        // There's an interesting vsock bug. When a new connection is created to the enclave in
        // the `handle_request_accept` function (from `ConnectionKey::from_vsock_stream`), the
        // local cid is different from the cid received when inspecting `enclave: VsockStream`.
        // Locating the cid of the runner through the `get_local_cid` does give the same result.
        // When PLAT-288 lands, the cid may also here be retrieved through the open runner-enclave
        // connection
        let runner_cid = vsock::get_local_cid().unwrap_or(vsock::VMADDR_CID_LOCAL);
        let runner = VsockAddr::new(runner_cid, runner_port);
        let k = ConnectionKey::from_addresses(enclave, runner);
        self.connections
            .read()
            .unwrap()
            .get(&k)
            .cloned()
    }

    fn add_connection(self: Arc<Self>, runner_enclave: VsockStream, runner_remote: TcpStream, remote_name: String) -> Result<JoinHandle<()>, IoError> {
        let k = ConnectionKey::from_vsock_stream(&runner_enclave)?;
        let mut connection = Connection::new(runner_enclave, runner_remote, remote_name);
        self.connections.write().unwrap().insert(k.clone(), connection.info()?);

        thread::Builder::new().spawn(move || {
            if let Err(e) = connection.proxy() {
                error!("Connection failed: {}", e);
            }
            self.connections.write().unwrap().remove(&k);
        })
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
    fn handle_request_bind(self: Arc<Self>, addr: &String, enclave_port: u32, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let cid: u32 = conn.peer_port()?;
        let listener = TcpListener::bind(addr)?;
        let local: Addr = listener.local_addr()?.into();
        self.add_listener(VsockAddr::new(cid, enclave_port), Listener::new(listener));
        conn.send(&Response::Bound{ local })?;
        Ok(())
    }

    fn handle_request_accept(self: Arc<Self>, vsock_listener_port: u32, client_conn: &mut ClientConnection) -> Result<(), VmeError> {
        let enclave_cid = client_conn.peer_port()?;
        let enclave_addr = VsockAddr::new(enclave_cid, vsock_listener_port);
        let listener = self.listener(&enclave_addr)
            .ok_or(IoError::new(IoErrorKind::InvalidInput, "Information about provided file descriptor was not found"))?;
        let listener = listener.lock().unwrap();
        let (conn, peer) = listener.listener.accept()?;
        let vsock = Vsock::new::<Std>()?;
        let runner_addr = vsock.addr::<Std>()?;
        client_conn.send(&Response::IncomingConnection{
            local: conn.local_addr()?.into(),
            peer: peer.into(),
            proxy_port: runner_addr.port(),
        })?;

        let connect = || -> Result<(), VmeError> {
            // Connect to enclave at the expected port
            let proxy = vsock.connect_with_cid_port(enclave_addr.cid(), enclave_addr.port())?;
            self.add_connection(proxy, conn, "remote".to_string())?;
            Ok(())
        };
        if let Err(e) = connect() {
            error!("Failed to connect to the enclave after it requested an accept: {:?}", e);
        }
        Ok(())
    }

    fn handle_request_close(self: Arc<Self>, enclave_port: u32, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let cid: u32 = conn.peer_port()?;
        let addr = VsockAddr::new(cid, enclave_port);
        if let Some(listener) = self.remove_listener(&addr) {
            // Close `TcpListener`
            drop(listener);
        } else {
            warn!("Can't close the connection as it can't be located.");
        }
        conn.send(&Response::Closed)?;
        Ok(())
    }

    fn handle_request_info(self: Arc<Self>, enclave_port: u32, runner_port: Option<u32>, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let enclave_cid = conn.peer_port()?;
        let enclave_addr = VsockAddr::new(enclave_cid, enclave_port);
        if let Some(runner_port) = runner_port {
            // We're looking for a Connection
            if let Some(ConnectionInfo{ local, peer }) = self.connection_info(enclave_addr, runner_port) {
                conn.send(&Response::Info {
                    local,
                    peer: Some(peer),
                })?;
                Ok(())
            } else {
                // Connection not found
                Err(VmeError::ConnectionNotFound)
            }
        } else {
            // We're looking for a Listener
            if let Some(listener) = self.listener(&enclave_addr) {
                let listener = listener.lock().unwrap();
                conn.send(&Response::Info {
                    local: listener.listener.local_addr()?.into(),
                    peer: None,
                })?;
                Ok(())
            } else {
                // Listener not found
                Err(VmeError::ConnectionNotFound)
            }
        }
    }

    fn handle_request_exit(self: Arc<Self>, exit_code: i32) -> Result<(), VmeError> {
        std::process::exit(exit_code);
    }

    fn handle_client(self: Arc<Self>, conn: &mut ClientConnection) -> Result<(), VmeError> {
        match conn.read_request()? {
            Request::Init                        => self.handle_request_init(conn),
            Request::Connect{ addr }             => self.handle_request_connect(&addr, conn),
            Request::Bind{ addr, enclave_port }  => self.handle_request_bind(&addr, enclave_port, conn),
            Request::Accept{ enclave_port }      => self.handle_request_accept(enclave_port, conn),
            Request::Info{
                enclave_port,
                runner_port }                    => self.handle_request_info(enclave_port, runner_port, conn),
            Request::Close{ enclave_port }       => self.handle_request_close(enclave_port, conn),
            Request::Exit{ code }                => self.handle_request_exit(code),
        }
    }

    fn bind(port: u32) -> io::Result<Self> {
        let command_listener = VsockListener::<Std>::bind_with_cid_port(vsock::VMADDR_CID_ANY, port)?;
        Ok(Server {
            enclave: RwLock::new(EnclaveState::Null),
            command_listener: Mutex::new(command_listener),
            listeners: RwLock::new(FnvHashMap::default()),
            connections: RwLock::new(FnvHashMap::default()),
        })
    }

    fn start_command_server(self: Arc<Self>) -> Result<JoinHandle<()>, IoError> {
        thread::Builder::new().spawn(move || {
            let command_listener = self.command_listener.lock().unwrap();
            for stream in command_listener.incoming() {
                let server = self.clone();
                let _ = thread::Builder::new()
                    .spawn(move || {
                        let mut conn = match stream {
                            Ok(stream) => ClientConnection::new(stream),
                            Err(e) => {
                                error!("Incoming connection failed: {:?}", e);
                                return;
                            }
                        };
                        if let Err(e) = server.handle_client(&mut conn) {
                            if let Err(e) = conn.send(&Response::Failed(e)) {
                                error!("Failed to send response to enclave: {:?}", e);
                            }
                        }
                    });
            }
        })
    }

    fn run_command_server(self: Arc<Self>) -> std::io::Result<JoinHandle<()>> {
        info!("Starting enclave runner.");
        let port = self.command_listener.lock().unwrap().local_addr()?.port();
        info!("Listening on vsock port {}...", port);

        let handle = self.start_command_server()?;
        Ok(handle)
    }

    /// Starts a new enclave
    pub fn run_enclave<I: Into<P::RunArgs>>(&self, run_args: I, enclave_args: Vec<String>) -> Result<(), VmeError> {
        let mut state = self.enclave.write().unwrap();
        match *state {
            EnclaveState::Running { .. } => panic!("Enclave already exists"),
            EnclaveState::Null => {
                let enclave = P::run(run_args)?;
                *state = EnclaveState::Running {
                    enclave,
                    args: enclave_args,
                };
            }
        }
        Ok(())
    }
}

