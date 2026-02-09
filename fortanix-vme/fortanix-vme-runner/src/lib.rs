#![deny(warnings)]
use enclave_runner::platform::{CommandConfiguration, EnclaveConfiguration, EnclavePlatform};
use fnv::FnvHashMap;
use futures::future::poll_fn;
use log::debug;
use log::{error, info, log, warn};
use nix::libc::VMADDR_PORT_ANY;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::{JoinError, JoinHandle};
use std::cmp;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::str;
use std::sync::Arc;
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind};
use tokio::sync::RwLock;
use fortanix_vme_abi::{self, Addr, Error as VmeError, Response, Request, SERVER_PORT};
use tokio_vsock::{self, VMADDR_CID_ANY, VMADDR_CID_LOCAL, VsockAddr, VsockListener, VsockStream};
use enclave_runner::stream_router::{AsyncListener, AsyncStream, OsStreamRouter, StreamRouter};

use fortanix_vme_abi::ErrorKind as VmeErrorKind;

mod platforms;
pub use platforms::{Platform, NitroEnclaves, Simulator, SimulatorArgs};

pub use fortanix_vme_eif::{read_eif_with_metadata, ReadEifResult};

#[derive(thiserror::Error, Debug)]
pub enum VmeRunnerError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Vme ABI error: {0:?}")]
    VmeAbiError(VmeError),
    #[error("Failed to join async handler: {0}")]
    Join(#[from] JoinError),
    #[error("Connection not found")]
    ConnectionNotFound,
    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error)
}

impl From<VmeError> for VmeRunnerError {
    fn from(value: VmeError) -> Self {
        VmeRunnerError::VmeAbiError(value)
    }
}

type SharedStreamRouter = Arc<dyn StreamRouter + Send + Sync>;

enum Direction {
    Left,
    Right,
}

pub trait StreamConnection: AsyncRead + AsyncWrite {
    fn protocol() -> &'static str;

    fn local(&self) -> io::Result<String>;

    fn local_port(&self) -> io::Result<u32>;

    fn peer(&self) -> io::Result<String>;

    fn peer_port(&self) -> io::Result<u32>;
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
    listener: Pin<Box<dyn AsyncListener>>,
    local: Addr,
}

impl Listener {
    fn new(listener: Box<dyn AsyncListener>, local: Addr) -> Self {
        Listener {
            listener: listener.into(),
            local,
        }
    }
}

struct Connection {
    remote_stream: Pin<Box<dyn AsyncStream>>,
    vsock_stream: VsockStream,
    remote_name: String,
    info: ConnectionInfo,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct ConnLogInfo {
    local_port: u32,
    peer_port: u32,
    protocol: &'static str,
}

impl ConnLogInfo {
    fn from_stream<S: StreamConnection>(stream: &S) -> Self {
        ConnLogInfo {
            local_port: stream.local_port().unwrap_or_default(),
            peer_port: stream.peer_port().unwrap_or_default(),
            protocol: S::protocol(),
        }
    }

    fn from_addr(protocol: &'static str, local: &Addr, peer: &Addr) -> Self {
        ConnLogInfo {
            local_port: addr_port(local),
            peer_port: addr_port(peer),
            protocol,
        }
    }
}

fn addr_port(addr: &Addr) -> u32 {
    match addr {
        Addr::IPv4 { port, .. } => *port as u32,
        Addr::IPv6 { port, .. } => *port as u32,
    }
}

fn addr_from_string(label: &str, addr: &str) -> Result<Addr, VmeError> {
    if addr.is_empty() || addr == "error" {
        error!("Missing {} address from stream router", label);
        return Err(VmeError::Command(VmeErrorKind::InvalidData));
    }
    let socket: SocketAddr = addr.parse().map_err(|err| {
        error!("Failed to parse {} address '{}' : {}", label, addr, err);
        VmeError::Command(VmeErrorKind::InvalidInput)
    })?;
    Ok(socket.into())
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    /// The local address (as used by the runner)
    local: Addr,
    /// The address of the remote party for open connection, None for server sockets
    peer: Addr,
}

impl Connection {
    pub fn new(
        vsock_stream: VsockStream,
        remote_stream: Box<dyn AsyncStream>,
        remote_name: String,
        info: ConnectionInfo,
    ) -> Self {
        Connection {
            remote_stream: Pin::from(remote_stream),
            vsock_stream,
            remote_name,
            info,
        }
    }

    pub async fn proxy(self) -> Result<(), IoError> {
        let Connection {
            mut remote_stream,
            mut vsock_stream,
            remote_name,
            info,
        } = self;
        let remote_info = ConnLogInfo::from_addr("tcp", &info.local, &info.peer);
        let enclave_info = ConnLogInfo::from_stream(&vsock_stream);
        debug!("Proxy started enclave: {:?}, {}: {:?}", enclave_info, remote_name, remote_info);

        let (remote_len, enclave_len) = tokio::io::copy_bidirectional(&mut remote_stream, &mut vsock_stream).await?;
        debug!("Proxy connection closed, total bytes proxied: remote {}, enclave {}", remote_len, enclave_len);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    enclave: VsockAddr,
}

impl ConnectionKey {
    pub fn from_vsock_stream(runner_enclave: &VsockStream) -> Result<Self, IoError> {
        let runner_cid = runner_enclave.local_addr()?.cid();
        let runner_port = runner_enclave.local_addr()?.port();
        let enclave_cid = runner_enclave.peer_addr()?.cid();
        let enclave_port = runner_enclave.peer_addr()?.port();
        Ok(Self::connection_key(enclave_cid, enclave_port, runner_cid, runner_port))
    }

    /// Note: We only use enclave's VsockAddr as hash map key.
    pub fn from_addresses(enclave: VsockAddr, _runner: VsockAddr) -> Self {
        ConnectionKey {
            enclave,
        }
    }

    fn connection_key(enclave_cid: u32, enclave_port: u32, runner_cid: u32, runner_port: u32) -> Self {
        let enclave = VsockAddr::new(enclave_cid, enclave_port);
        let runner = VsockAddr::new(runner_cid, runner_port);
        Self::from_addresses(enclave, runner)
    }
}

pub struct ClientConnection {
    stream: VsockStream,
}

impl ClientConnection {
    pub fn new(stream: VsockStream) -> Self {
        ClientConnection {
            stream,
        }
    }

    pub fn peer_port(&self) -> Result<u32, IoError> {
        self.stream
            .peer_addr()
            .map(|addr| addr.port())
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

    pub async fn send(&mut self, response: &Response) -> Result<(), IoError> {
        Self::log_communication(
            log::Level::Info,
            "runner",
            self.stream.local_port().unwrap_or_default(),
            "enclave",
            self.stream.peer_port().unwrap_or_default(),
            &format!("{:?}", response),
            Direction::Right,
            "vsock",
            None);
        let response: Vec<u8> = serde_cbor::ser::to_vec(response)
                                    .map_err(|_| IoError::new(IoErrorKind::InvalidData, "Serialization failed"))?;
        self.stream.write_all(&response.len().to_le_bytes()).await?;
        self.stream.write_all(&response).await?;
        Ok(())
    }

    pub async fn read_request(&mut self) -> Result<Request, IoError> {
        let mut size = [0u8; usize::BITS as usize / 8];
        self.stream.read_exact(&mut size[..]).await?;
        let size = usize::from_le_bytes(size);

        let mut req = Vec::new();
        req.resize(size, 0);
        self.stream.read_exact(&mut req).await?;
        let req = serde_cbor::from_slice(&req)
            .map_err(|e| IoError::new(IoErrorKind::InvalidInput, e))?;

        Self::log_communication(
            log::Level::Info,
            "runner",
            self.stream.local_port().unwrap_or_default(),
            "enclave",
            self.stream.peer_port().unwrap_or_default(),
            &format!("{:?}", &req),
            Direction::Left,
            "vsock",
            None);
        Ok(req)
    }
}

pub struct EnclaveRunner<P: Platform> {
    platform: PhantomData<P>,
    stream_router: SharedStreamRouter,
}

impl<P: Platform + 'static> EnclaveRunner<P> {
    /// Creates a new enclave runner
    pub fn new() -> Self {
        Self { platform: PhantomData, stream_router: Arc::from(OsStreamRouter::new()) }
    }

    pub fn with_stream_router(&mut self, router: Box<dyn StreamRouter + Send + Sync>) -> &mut Self {
        self.stream_router = Arc::from(router);
        self
    }

    /// Starts a new enclave
    pub async fn run_enclave<I: Into<P::RunArgs> + Send + 'static>(&mut self, run_args: I, enclave_name: String, enclave_args: Vec<String>, forward_panics: bool) -> Result<(), VmeRunnerError> {
        let server = Server::<P>::bind(enclave_name, SERVER_PORT, self.stream_router.clone(), forward_panics)?;
        let command_server_handle = server.start_command_server()?;
        server.run_enclave(run_args, enclave_args).await?;
        command_server_handle.await?;
        Ok(())
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
    name: String,
    command_listener_local_addr: VsockAddr,
    state: Arc<ServerState<P>>,
}

pub struct ServerState<P: Platform> {
    forward_panics: bool,
    enclave_state: RwLock<EnclaveState<P>>,
    command_listener: VsockListener,
    stream_router: SharedStreamRouter,
    /// Tracks information about TCP sockets that are currently listening for new connections. For
    /// every TCP listener socket in the runner, there is a vsock listener socket in the enclave.
    /// When the enclave instructs to accept a new connection, the runner accepts a new TCP
    /// connection. It then locates the ListenerInfo and finds the information it needs to set up a
    /// new vsock connection to the enclave
    listeners: RwLock<FnvHashMap<VsockAddr, Arc<Mutex<Listener>>>>,
    connections: Arc<RwLock<FnvHashMap<ConnectionKey, ConnectionInfo>>>,
}

impl<P: Platform + 'static> ServerState<P> {
    async fn handle_request_init(self: &Self, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let state = self.enclave_state.read().await;
        let args = match &*state {
            EnclaveState::Null => panic!("Not yet running enclave requesting initialization"),
            EnclaveState::Running { args, .. } => args.to_owned(),
        };
        let response = Response::Init {
            args,
        };
        conn.send(&response).await?;
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
    async fn handle_request_connect(self: &Self, remote_addr: &String, conn: &mut ClientConnection) -> Result<(), VmeError> {
        // Connect to remote server
        let mut local_addr_str = String::new();
        let mut peer_addr_str = String::new();
        let remote_stream = self.stream_router
            .connect_stream(remote_addr, Some(&mut local_addr_str), Some(&mut peer_addr_str))
            .await
            .map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string("local", &local_addr_str)?;
        let peer = addr_from_string("peer", &peer_addr_str)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr).to_owned();

        // Create listening socket that the enclave can connect to
        let proxy_server = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY))?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
            proxy_port: proxy_server_port,
            local: local.clone(),
            peer: peer.clone(),
        };

        conn.send(&response).await?;

        // Wait for incoming connection from enclave. Unfortunately, we can't send a second
        // response with an error message back to the enclave when something goes wrong anymore.
        // We'll log the problem instead
        let accept_connection = async move || -> Result<(), VmeRunnerError> {
            let (proxy, _proxy_addr) = proxy_server.accept().await?;
            // Store connection info
            self.add_connection(proxy, remote_stream, remote_name, ConnectionInfo { local, peer }).await?;
            Ok(())
        };
        if let Err(e) = accept_connection().await {
            error!("Failed to accept connection from the enclave: {:?}", e);
        }
        Ok(())
    }

    async fn add_listener(&self, addr: VsockAddr, info: Listener) {
        self.listeners.write().await.insert(addr, Arc::new(Mutex::new(info)));
    }

    async fn listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.read().await.get(&addr).cloned()
    }

    async fn remove_listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.write().await.remove(&addr)
    }

    async fn connection_info(&self, enclave: VsockAddr, runner_port: u32) -> Option<ConnectionInfo> {
        // There's an interesting vsock bug. When a new connection is created to the enclave in
        // the `handle_request_accept` function (from `ConnectionKey::from_vsock_stream`), the
        // local cid is different from the cid received when inspecting `enclave: VsockStream`.
        // Locating the cid of the runner through the `get_local_cid` does give the same result.
        // When PLAT-288 lands, the cid may also here be retrieved through the open runner-enclave
        // connection
        let runner_cid = vsock::get_local_cid().unwrap_or(VMADDR_CID_LOCAL);
        let runner = VsockAddr::new(runner_cid, runner_port);
        let k = ConnectionKey::from_addresses(enclave, runner);
        self.connections
            .read()
            .await
            .get(&k)
            .cloned()
    }

    async fn remove_connection(self: &Self, enclave_addr: &VsockAddr) -> Option<ConnectionInfo> {
        let k = ConnectionKey::from_addresses(enclave_addr.clone(), enclave_addr.clone());
        self.connections.write().await.remove(&k)
    }

    async fn add_connection(
        self: &Self,
        runner_enclave: VsockStream,
        runner_remote: Box<dyn AsyncStream>,
        remote_name: String,
        info: ConnectionInfo,
    ) -> Result<JoinHandle<()>, IoError> {
        let k = ConnectionKey::from_vsock_stream(&runner_enclave)?;
        let connection = Connection::new(runner_enclave, runner_remote, remote_name, info.clone());
        self.connections.write().await.insert(k.clone(), info);

        let connections = self.connections.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = connection.proxy().await {
                error!("Connection failed: {}", e);
            }
            connections.write().await.remove(&k);
        });
        Ok(handle)
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
    async fn handle_request_bind(self: &Self, addr: &String, enclave_port: u32, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let cid: u32 = conn.stream.peer_addr()?.cid();
        let mut local_addr_str = String::new();
        let listener = self.stream_router
            .bind_stream(addr, Some(&mut local_addr_str))
            .await
            .map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string("local", &local_addr_str)?;
        self.add_listener(VsockAddr::new(cid, enclave_port), Listener::new(listener, local.clone())).await;
        conn.send(&Response::Bound{ local }).await?;
        Ok(())
    }

    async fn handle_request_accept(self: &Self, vsock_listener_port: u32, client_conn: &mut ClientConnection) -> Result<(), VmeError> {
        use nix::{errno::Errno, sys::socket};

        fn nix_to_vme_error(errno: Errno) -> VmeError {
            VmeError::SystemError(errno as i32)
        }

        fn vsock_create_bind(runner_port: u32, runner_cid: u32) -> Result<vsock::VsockStream, VmeError> {
            let socket = unsafe {
                use std::os::fd::{IntoRawFd, FromRawFd};
                let socket = socket::socket(socket::AddressFamily::Vsock, socket::SockType::Stream, socket::SockFlag::SOCK_CLOEXEC | socket::SockFlag::SOCK_NONBLOCK, None).map_err(nix_to_vme_error)?;
                vsock::VsockStream::from_raw_fd(socket.into_raw_fd())
            };

            let runner_addr = socket::VsockAddr::new(runner_cid, runner_port);
            socket::bind(socket.as_raw_fd(), &runner_addr).map_err(nix_to_vme_error)?;

            Ok(socket)
        }

        async fn vsock_connect(socket: vsock::VsockStream, enclave_cid: u32, enclave_port: u32) -> Result<VsockStream, VmeError> {
            let enclave_addr = socket::VsockAddr::new(enclave_cid, enclave_port);
            let mut res = socket::connect(socket.as_raw_fd(), &enclave_addr);
            if res == Err(Errno::EINPROGRESS) {
                res = Ok(())
            };
            res.map_err(nix_to_vme_error)?;

            let fd = tokio::io::unix::AsyncFd::new(socket)?;
            let _ = fd.writable().await?;

            let socket = VsockStream::new(fd.into_inner())?;
            Ok(socket)
        }

        // Locate TCP listener
        let enclave_cid = client_conn.stream.peer_addr()?.cid();
        let enclave_addr = VsockAddr::new(enclave_cid, vsock_listener_port);

        let listener = self.listener(&enclave_addr).await
            .ok_or(IoError::new(IoErrorKind::InvalidInput, "Information about provided file descriptor was not found"))?;

        // Accept connection for listener
        let mut listener = listener.lock().await;
        let mut local_addr_str = String::new();
        let mut peer_addr_str = String::new();
        let conn = accept_stream(
            &mut listener.listener,
            Some(&mut local_addr_str),
            Some(&mut peer_addr_str),
        ).await.map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string("local", &local_addr_str)?;
        let peer = addr_from_string("peer", &peer_addr_str)?;
        drop(listener);

        // Send enclave info where it should accept new incoming connection
        let runner_vsock_socket = vsock_create_bind(VMADDR_PORT_ANY, VMADDR_CID_ANY)?;
        let runner_port = runner_vsock_socket.local_addr()?.port();
        client_conn.send(&Response::IncomingConnection{
            local: local.clone(),
            peer: peer.clone(),
            proxy_port: runner_port,
        }).await?;

        let connect = async || -> Result<(), VmeError> {
            // Connect to enclave at the expected port
            let proxy = vsock_connect(runner_vsock_socket, enclave_cid, vsock_listener_port).await?;
            self.add_connection(proxy, conn, "remote".to_string(), ConnectionInfo { local, peer }).await?;
            Ok(())
        };
        if let Err(e) = connect().await {
            error!("Failed to connect to the enclave after it requested an accept: {:?}", e);
        }
        Ok(())
    }

    async fn handle_request_close(self: &Self, enclave_port: u32, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let cid: u32 = conn.stream.peer_addr()?.cid();
        let addr = VsockAddr::new(cid, enclave_port);
        if let Some(listener) = self.remove_listener(&addr).await {
            // Close `TcpListener`
            drop(listener);
        } else if let Some(conn) = self.remove_connection(&addr).await {
            // Close TcpStream
            drop(conn);
        } else {
            // Close TcpStream?
            warn!("Can't close the connection as it can't be located.");
        }
        conn.send(&Response::Closed).await?;
        Ok(())
    }

    async fn handle_request_info(self: &Self, enclave_port: u32, runner_port: Option<u32>, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let enclave_cid = conn.peer_port()?;
        let enclave_addr = VsockAddr::new(enclave_cid, enclave_port);
        if let Some(runner_port) = runner_port {
            // We're looking for a Connection
            if let Some(ConnectionInfo{ local, peer }) = self.connection_info(enclave_addr, runner_port).await {
                conn.send(&Response::Info {
                    local,
                    peer: Some(peer),
                }).await?;
                Ok(())
            } else {
                // Connection not found
                Err(VmeError::ConnectionNotFound)
            }
        } else {
            // We're looking for a Listener
            if let Some(listener) = self.listener(&enclave_addr).await {
                let listener = listener.lock().await;
                conn.send(&Response::Info {
                    local: listener.local.clone(),
                    peer: None,
                }).await?;
                Ok(())
            } else {
                // Listener not found
                Err(VmeError::ConnectionNotFound)
            }
        }
    }

    fn handle_request_exit(self: &Self, exit_code: i32) -> Result<(), VmeError> {
        if self.forward_panics && exit_code != 0 {
            panic!("enclave panic with exit code: {}", exit_code);
        } else {
            std::process::exit(exit_code);
        }
    }

    async fn handle_client(self: &Self, conn: &mut ClientConnection) -> Result<(), VmeError> {
        match conn.read_request().await.or_else(|e| { error!("read_request error: {:?}", e); Err(e) } )? {
            Request::Init                        => self.handle_request_init(conn).await
                                                        .or_else(|e| { error!("init error: {:?}", e); Err(e) }),
            Request::Connect{ addr }             => self.handle_request_connect(&addr, conn).await
                                                        .or_else(|e| { error!("connect error: {:?}", e); Err(e) }),
            Request::Bind{ addr, enclave_port }  => self.handle_request_bind(&addr, enclave_port, conn).await
                                                        .or_else(|e| { error!("bind error: {:?}", e); Err(e) }),
            Request::Accept{ enclave_port }      => self.handle_request_accept(enclave_port, conn).await
                                                        .or_else(|e| { error!("accept error: {:?}", e); Err(e) }),
            Request::Info{
                enclave_port,
                runner_port }                    => self.handle_request_info(enclave_port, runner_port, conn).await
                                                        .or_else(|e| { error!("info error: {:?}", e); Err(e) }),
            Request::Close{ enclave_port }       => self.handle_request_close(enclave_port, conn).await
                                                        .or_else(|e| { error!("close error: {:?}", e); Err(e) }),
            Request::Exit{ code }                => self.handle_request_exit(code)
                                                        .or_else(|e| { error!("exit error: {:?}", e); Err(e) }),
        }
    }
}

async fn accept_stream(
    listener: &mut Pin<Box<dyn AsyncListener>>,
    mut local_addr: Option<&mut String>,
    mut peer_addr: Option<&mut String>,
) -> io::Result<Box<dyn AsyncStream>> {
    poll_fn(|cx| {
        let local = local_addr.as_mut().map(|addr| &mut **addr);
        let peer = peer_addr.as_mut().map(|addr| &mut **addr);
        listener.as_mut().poll_accept(cx, local, peer)
    }).await
}

impl<P: Platform + 'static> Server<P> {
    fn bind(enclave_name: String, port: u32, stream_router: SharedStreamRouter, forward_panics: bool) -> Result<Self, VmeRunnerError> {
        let command_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        let command_listener_local_addr = command_listener.local_addr()?;
        Ok(Server {
            name: enclave_name,
            command_listener_local_addr,
            state: Arc::new(ServerState { 
                forward_panics,
                enclave_state: RwLock::new(EnclaveState::Null),
                command_listener,
                stream_router,
                listeners: RwLock::new(FnvHashMap::default()),
                connections: Arc::new(RwLock::new(FnvHashMap::default())),
            })
        })
    }

    fn start_command_server(self: &Self) -> Result<tokio::task::JoinHandle<()>, VmeRunnerError> {
        info!("Starting enclave runner.");
        info!("Command server listening on vsock cid: {} port: {} ...", self.command_listener_local_addr.cid(), self.command_listener_local_addr.port());
        let state = self.state.clone();
        let handle = tokio::spawn(
            async move {
                loop {
                    let state_for_conn = state.clone();
                    let accepted = state.command_listener.accept().await;
                    let _ = tokio::spawn(async move {
                       let mut conn = match accepted {
                            Ok((stream, _addr)) => ClientConnection::new(stream),
                            Err(e) => {
                                error!("Incoming connection failed: {:?}", e);
                                return;
                            }
                        };
                        if let Err(e) = state_for_conn.handle_client(&mut conn).await {
                            error!("Original error: {:?}", e);
                            if let Err(e) = conn.send(&Response::Failed(e)).await {
                                error!("Failed to send response to enclave: {:?}", e);
                            }
                        }; 
                    });
                }
            }
        );
        Ok(handle)
    }

    /// Starts a new enclave
    pub async fn run_enclave<I: Into<P::RunArgs> + Send + 'static>(&self, run_args: I, mut enclave_args: Vec<String>) -> Result<(), VmeRunnerError> {
        let mut state = self.state.enclave_state.write().await;
        match *state {
            EnclaveState::Running { .. } => panic!("Enclave already exists"),
            EnclaveState::Null => {
                enclave_args.insert(0, self.name.clone());
                // Assume Platform::run will do some blocking logic
                let handle = tokio::task::spawn_blocking(|| P::run(run_args));
                let ret = handle.await?;
                let enclave = ret?;
                *state = EnclaveState::Running {
                    enclave,
                    args: enclave_args,
                };
            }
        }
        Ok(())
    }
}

pub struct EnclaveBuilder<P: Platform, Args: Into<P::RunArgs>> {
    runner: EnclaveRunner<P>,
    runner_args: Args,
    enclave_name: String,
}

impl<P: Platform + 'static, Args: Into<P::RunArgs>> EnclaveBuilder<P, Args> {
    pub fn new(runner_args: Args, enclave_name: String) -> Result<Self, anyhow::Error> {
        let runner = EnclaveRunner::<P>::new();
        Ok(Self { runner, runner_args, enclave_name })
    }
}

impl<P: Platform + 'static, Args: Into<P::RunArgs> + 'static + Send> EnclavePlatform<enclave_runner::Command> for EnclaveBuilder<P, Args> {
    type Loader = ();

    fn build(
        self,
        _loader: Self::Loader,
        configuration: EnclaveConfiguration,
        mut cmd_configuration: CommandConfiguration
    ) -> Result<enclave_runner::Command, anyhow::Error>
    {
        // By default: cmd_args[0] == "enclave", where `enclave` is process name.
        // In VME runner we will use inject image name at index 0 as process name, so remove it here.
        cmd_configuration.cmd_args.remove(0);
        Ok(command::Command::internal_new(self, configuration.stream_router, configuration.forward_panics, cmd_configuration))
    }
}

mod command {
    use enclave_runner::stream_router::StreamRouter;

    use super::*;

    pub struct Command {
        _private: (),
    }

    impl Command {
        pub(crate) fn internal_new<P: Platform + 'static, Args: Into<P::RunArgs> + 'static + Send>(
            enclave_builder: EnclaveBuilder<P, Args>,
            stream_router: Box<dyn StreamRouter + Send + Sync>,
            forward_panics: bool,
            cmd_configuration: CommandConfiguration,
        ) -> enclave_runner::Command {
            (Box::new(move || -> Result<(), anyhow::Error> {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?.
                    block_on(async move {
                        let EnclaveBuilder { mut runner, runner_args, enclave_name } = enclave_builder;
                        runner.stream_router = stream_router.into();

                        let enclave_args = cmd_configuration.cmd_args.into_iter().map(|arr| String::from_utf8(arr)).collect::<Result<Vec<_>, _>>()?;
                        runner.run_enclave(runner_args, enclave_name, enclave_args, forward_panics).await?;
                        Ok(())
                    })
            }) as Box<dyn FnOnce() -> _>)
            .into()
        }
    }
}