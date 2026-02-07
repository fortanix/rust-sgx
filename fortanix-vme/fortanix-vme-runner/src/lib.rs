#![deny(warnings)]
use enclave_runner::platform::{CommandConfiguration, EnclaveConfiguration, EnclavePlatform};
use fnv::FnvHashMap;
use futures::future::try_join_all;
use log::debug;
use log::{error, info, log, warn};
use nix::libc::VMADDR_PORT_ANY;
use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::{JoinError, JoinHandle};
use std::cmp;
use std::fmt::Debug;
use std::os::fd::AsRawFd;
use std::str;
use std::sync::Arc;
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind};
use tokio::sync::RwLock;
use fortanix_vme_abi::{self, Addr, Error as VmeError, Response, Request, SERVER_PORT};
use tokio_vsock::{self, VMADDR_CID_ANY, VMADDR_CID_LOCAL, VsockAddr, VsockListener, VsockStream};

mod platforms;
pub use platforms::{Platform, NitroEnclaves, Simulator, SimulatorArgs};

pub use fortanix_vme_eif::{read_eif_with_metadata, ReadEifResult};

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

#[derive(Debug)]
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
    vsock_stream: VsockStream,
    remote_name: String,
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    /// The local address (as used by the runner)
    local: Addr,
    /// The address of the remote party for open connection, None for server sockets
    peer: Addr,
}

fn log_proxy_conn_info<S: StreamConnection, D: StreamConnection>(level: log::Level, enclave: &S, enclave_name:&str, remote: &D, remote_name:&str) {
    log!(level, "Proxy started remote : {}, local: {}, peer: {}", remote_name, remote.local().unwrap_or_default(), remote.peer().unwrap_or_default());
    log!(level, "Proxy started enclave: {}, local: {}, peer: {}", enclave_name, enclave.local().unwrap_or_default(), enclave.peer().unwrap_or_default());
}


impl Connection {
    pub fn new(vsock_stream: VsockStream, tcp_stream: TcpStream, remote_name: String) -> Self {
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

    pub async fn proxy(&mut self) -> Result<(), IoError> {
        log_proxy_conn_info(log::Level::Debug, &self.vsock_stream, "enclave", &self.tcp_stream, &self.remote_name);
        let (remote_len, enclave_len) = tokio::io::copy_bidirectional(&mut self.tcp_stream, &mut self.vsock_stream).await?;
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
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e))
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
    servers: Vec<(Arc<Server<P>>, JoinHandle<()>)>,
}

impl<P: Platform + 'static> EnclaveRunner<P> {
    /// Creates a new enclave runner
    pub fn new() -> EnclaveRunner<P> {
        EnclaveRunner {
            servers: Vec::new(),
        }
    }

    /// Starts a new enclave
    pub async fn run_enclave<I: Into<P::RunArgs> + Send + 'static>(&mut self, run_args: I, enclave_name: String, enclave_args: Vec<String>) -> Result<(), VmeError> {
        let server = Arc::new(Server::bind(enclave_name, SERVER_PORT)?);
        let server_thread = server.clone().start_command_server()?;
        server.run_enclave(run_args, enclave_args).await?;
        self.servers.push((server, server_thread));
        Ok(())
    }

    /// Blocks the current thread until the command thread exits
    pub async fn wait(self) {
        let handles: Vec<_> =
            self.servers.into_iter().map(|(_, h)| h).collect();
        let _ = join_all(handles).await;
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
    enclave: RwLock<EnclaveState<P>>,
    command_listener: Mutex<VsockListener>,
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
        let state = self.enclave.read().await;
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
        let remote_socket = TcpStream::connect(remote_addr).await.map_err(|e| VmeError::Command(e.kind().into()))?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let proxy_server = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY))?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
            proxy_port: proxy_server_port,
            local: remote_socket.local_addr()?.into(),
            peer: remote_socket.peer_addr()?.into(),
        };

        conn.send(&response).await?;

        // Wait for incoming connection from enclave. Unfortunately, we can't send a second
        // response with an error message back to the enclave when something goes wrong anymore.
        // We'll log the problem instead
        let accept_connection = async move || -> Result<(), VmeError> {
            let (proxy, _proxy_addr) = proxy_server.accept().await?;
            // Store connection info
            self.add_connection(proxy, remote_socket, remote_name.to_string()).await?;
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

    async fn add_connection(self: &Self, runner_enclave: VsockStream, runner_remote: TcpStream, remote_name: String) -> Result<JoinHandle<()>, IoError> {
        let k = ConnectionKey::from_vsock_stream(&runner_enclave)?;
        let mut connection = Connection::new(runner_enclave, runner_remote, remote_name);
        self.connections.write().await.insert(k.clone(), connection.info()?);

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
        let listener = TcpListener::bind(addr).await.map_err(|e| VmeError::Command(e.kind().into()))?;
        let local: Addr = listener.local_addr()?.into();
        self.add_listener(VsockAddr::new(cid, enclave_port), Listener::new(listener)).await;
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

        // Accept connection for TCP Listener
        let listener = listener.lock().await;
        let (conn, peer) = listener.listener.accept().await.map_err(|e| VmeError::Command(e.kind().into()))?;
        drop(listener);

        // Send enclave info where it should accept new incoming connection
        let runner_vsock_socket = vsock_create_bind(VMADDR_PORT_ANY, VMADDR_CID_ANY)?;
        let runner_port = runner_vsock_socket.local_addr()?.port();
        client_conn.send(&Response::IncomingConnection{
            local: conn.local_addr()?.into(),
            peer: peer.into(),
            proxy_port: runner_port,
        }).await?;

        let connect = async || -> Result<(), VmeError> {
            // Connect to enclave at the expected port
            let proxy = vsock_connect(runner_vsock_socket, enclave_cid, vsock_listener_port).await?;
            self.add_connection(proxy, conn, "remote".to_string()).await?;
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
                    local: listener.listener.local_addr()?.into(),
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
        std::process::exit(exit_code);
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

impl<P: Platform + 'static> Server<P> {
    fn bind(enclave_name: String, port: u32) -> io::Result<Self> {
        let command_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port))?;
        let command_listener_local_addr = command_listener.local_addr()?;
        Ok(Server {
            name: enclave_name,
            command_listener_local_addr,
            state: Arc::new(ServerState { 
                enclave: RwLock::new(EnclaveState::Null),
                command_listener: Mutex::new(command_listener),
                listeners: RwLock::new(FnvHashMap::default()),
                connections: Arc::new(RwLock::new(FnvHashMap::default())),
            })
        })
    }

    fn start_command_server(self: &Self) -> Result<tokio::task::JoinHandle<()>, IoError> {
        info!("Starting enclave runner.");
        info!("Command server listening on vsock cid: {} port: {} ...", self.command_listener_local_addr.cid(), self.command_listener_local_addr.port());
        let state = self.state.clone();
        let handle = tokio::spawn(
            async move {
                let command_listener = state.command_listener.lock().await;
                loop {
                    let accepted = command_listener.accept().await;
                    let state_for_conn = state.clone();
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
    pub async fn run_enclave<I: Into<P::RunArgs> + Send + 'static>(&self, run_args: I, mut enclave_args: Vec<String>) -> Result<(), VmeError> {
        let mut state = self.state.enclave.write().await;
        match *state {
            EnclaveState::Running { .. } => panic!("Enclave already exists"),
            EnclaveState::Null => {
                enclave_args.insert(0, self.name.clone());
                // Assume Platform::run will do some blocking logic
                let handle = tokio::task::spawn_blocking(|| P::run(run_args));
                let enclave = handle.await.expect("Failed to run enclave")?;
                *state = EnclaveState::Running {
                    enclave,
                    args: enclave_args,
                };
            }
        }
        Ok(())
    }
}

fn vme_error_to_string(err: VmeError) -> anyhow::Error {
    anyhow::anyhow!("{err:?}")
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
        // cmd_args by default have an b"enclave" in it which is not needed
        cmd_configuration.cmd_args.clear();
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
            _stream_router: Box<dyn StreamRouter>,
            _forward_panics: bool,
            cmd_configuration: CommandConfiguration,
        ) -> enclave_runner::Command {
            (Box::new(move || -> Result<(), anyhow::Error> {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?.
                    block_on(async move {
                        let EnclaveBuilder { mut runner, runner_args, enclave_name } = enclave_builder;
                        let enclave_args = cmd_configuration.cmd_args.into_iter().map(|arr| String::from_utf8(arr)).collect::<Result<Vec<_>, _>>()?;
                        runner.run_enclave(runner_args, enclave_name, enclave_args).await.map_err(vme_error_to_string)?;
                        runner.wait().await?;
                        Ok(())
                    })
            }) as Box<dyn FnOnce() -> _>)
            .into()
        }
    }
}