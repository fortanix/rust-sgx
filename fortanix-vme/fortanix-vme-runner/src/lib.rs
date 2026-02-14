#![deny(warnings)]
use enclave_runner::platform::{CommandConfiguration, EnclaveConfiguration, EnclavePlatform};
use enclave_runner::stream_router::{AsyncListener, AsyncStream, StreamRouter};
use fnv::FnvHashMap;
use fortanix_vme_abi::{self, Addr, Error as VmeError, Request, Response, SERVER_PORT};
use futures::future::poll_fn;
use log::debug;
use log::{error, info, log, warn};
use nix::libc::VMADDR_PORT_ANY;
use std::borrow::Cow;
use std::cmp;
use std::fmt::{Debug, Display};
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::str;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::task::{JoinError, JoinHandle};
use tokio_vsock::{self, VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_LOCAL};

mod platforms;
pub use platforms::amdsevsnp::{AmdSevVm, RunningVm, VmRunArgs, VmSimulator};
pub use platforms::{EnclaveSimulator, EnclaveSimulatorArgs, NitroEnclaves, Platform};

pub use confidential_vm_blobs::{AMD_SEV_OVMF_PATH, VANILLA_OVMF_PATH};
pub use fortanix_vme_eif::{read_eif_with_metadata, ReadEifResult};

#[derive(thiserror::Error, Debug)]
pub enum RunnerError {
    #[error("io error occurred: {0:?}")]
    Io(Option<Cow<'static, str>>, #[source] io::Error),
    #[error("vme ABI error: {0:?}")]
    VmeAbiError(VmeError),
    #[error("failed to join async handler: {0}")]
    Join(#[from] JoinError),
    #[error("connection not found")]
    ConnectionNotFound,
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),
    #[error("no available cid found")]
    NoAvailableCidFound,
}

impl From<VmeError> for RunnerError {
    fn from(value: VmeError) -> Self {
        RunnerError::VmeAbiError(value)
    }
}

// TODO (RTE-770): more accurate variant selection through `ErrorKind`
impl<I> From<(io::Error, I)> for RunnerError
where
    I: Into<Cow<'static, str>>,
{
    fn from((e, ctx): (io::Error, I)) -> Self
    where
        I: Into<Cow<'static, str>>,
    {
        RunnerError::Io(Some(ctx.into()), e)
    }
}

// TODO (RTE-770): get rid of this impl once we have multiple IO variants
impl From<io::Error> for RunnerError {
    fn from(value: io::Error) -> Self {
        RunnerError::Io(None, value)
    }
}

type BoxedStreamRouter = Box<dyn StreamRouter + Send + Sync>;

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

#[derive(Clone, Copy, Debug)]
struct ConnLogInfo {
    local_port: u32,
    peer_port: u32,
    protocol: &'static str,
}

impl Display for ConnLogInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{} ({} -> {})]",
            self.protocol, self.local_port, self.peer_port
        )
    }
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
            local_port: local.port() as u32,
            peer_port: peer.port() as u32,
            protocol,
        }
    }
}

const UNSPECIFIED_SOCKET_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
// TODO: It's a bug in the current VME protocol that it can't properly represent
// all possible addresses that a StreamRouter may return. #874 will address
// this. In the mean time, this function needs to always succeed.
fn addr_from_string(addr: &str) -> Addr {
    let socket: SocketAddr = addr.parse().unwrap_or(UNSPECIFIED_SOCKET_ADDR);
    socket.into()
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
        debug!(
            "Proxy started, enclave: {}, {}: {}",
            enclave_info, remote_name, remote_info
        );

        let (remote_len, enclave_len) =
            tokio::io::copy_bidirectional(&mut remote_stream, &mut vsock_stream).await?;
        debug!(
            "Proxy connection closed, total bytes proxied: remote {}, enclave {}",
            remote_len, enclave_len
        );
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
        Ok(Self::connection_key(
            enclave_cid,
            enclave_port,
            runner_cid,
            runner_port,
        ))
    }

    /// Note: We only use enclave's VsockAddr as hash map key.
    pub fn from_addresses(enclave: VsockAddr, _runner: VsockAddr) -> Self {
        ConnectionKey { enclave }
    }

    fn connection_key(
        enclave_cid: u32,
        enclave_port: u32,
        runner_cid: u32,
        runner_port: u32,
    ) -> Self {
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
        ClientConnection { stream }
    }

    pub fn peer_port(&self) -> Result<u32, IoError> {
        self.stream
            .peer_addr()
            .map(|addr| addr.port())
            .map_err(|e| IoError::new(IoErrorKind::InvalidData, e))
    }

    fn log_communication(
        level: log::Level,
        src: &str,
        src_port: u32,
        dst: &str,
        dst_port: u32,
        msg: &str,
        arrow: Direction,
        prot: &str,
        max_len: Option<usize>,
    ) {
        let src = format!("{}:{}", src, src_port);
        let dst = format!("{}:{}", dst, dst_port);
        let msg = if let Some(max) = max_len {
            &msg[0..cmp::min(msg.len(), max)]
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
            None,
        );
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
        let req =
            serde_cbor::from_slice(&req).map_err(|e| IoError::new(IoErrorKind::InvalidInput, e))?;

        Self::log_communication(
            log::Level::Info,
            "runner",
            self.stream.local_port().unwrap_or_default(),
            "enclave",
            self.stream.peer_port().unwrap_or_default(),
            &format!("{:?}", &req),
            Direction::Left,
            "vsock",
            None,
        );
        Ok(req)
    }
}

pub struct ServerState {
    forward_panics: bool,
    enclave_args: Vec<String>,
    command_listener: VsockListener,
    stream_router: BoxedStreamRouter,
    /// Tracks information about TCP sockets that are currently listening for new connections. For
    /// every TCP listener socket in the runner, there is a vsock listener socket in the enclave.
    /// When the enclave instructs to accept a new connection, the runner accepts a new TCP
    /// connection. It then locates the ListenerInfo and finds the information it needs to set up a
    /// new vsock connection to the enclave
    listeners: RwLock<FnvHashMap<VsockAddr, Arc<Mutex<Listener>>>>,
    connections: Arc<RwLock<FnvHashMap<ConnectionKey, ConnectionInfo>>>,
}

impl ServerState {
    async fn handle_request_init(self: &Self, conn: &mut ClientConnection) -> Result<(), VmeError> {
        let response = Response::Init {
            args: self.enclave_args.clone(),
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
    async fn handle_request_connect(
        self: &Self,
        remote_addr: &String,
        conn: &mut ClientConnection,
    ) -> Result<(), VmeError> {
        // Connect to remote server
        let mut local_addr_str = String::new();
        let mut peer_addr_str = String::new();
        let remote_stream = self
            .stream_router
            .connect_stream(
                remote_addr,
                Some(&mut local_addr_str),
                Some(&mut peer_addr_str),
            )
            .await
            .map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string(&local_addr_str);
        let peer = addr_from_string(&peer_addr_str);
        let remote_name = remote_addr
            .split_terminator(":")
            .next()
            .unwrap_or(remote_addr)
            .to_owned();

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
        let accept_connection = async move {
            let (proxy, _proxy_addr) = proxy_server.accept().await?;
            // Store connection info
            self.add_connection(
                proxy,
                remote_stream,
                remote_name,
                ConnectionInfo { local, peer },
            )
            .await?;
            Ok::<(), VmeError>(())
        };
        if let Err(e) = accept_connection.await {
            error!("Failed to accept connection from the enclave: {:?}", e);
        }
        Ok(())
    }

    async fn add_listener(&self, addr: VsockAddr, info: Listener) {
        self.listeners
            .write()
            .await
            .insert(addr, Arc::new(Mutex::new(info)));
    }

    async fn listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.read().await.get(&addr).cloned()
    }

    async fn remove_listener(&self, addr: &VsockAddr) -> Option<Arc<Mutex<Listener>>> {
        self.listeners.write().await.remove(&addr)
    }

    async fn connection_info(
        &self,
        enclave: VsockAddr,
        runner_port: u32,
    ) -> Option<ConnectionInfo> {
        // There's an interesting vsock bug. When a new connection is created to the enclave in
        // the `handle_request_accept` function (from `ConnectionKey::from_vsock_stream`), the
        // local cid is different from the cid received when inspecting `enclave: VsockStream`.
        // Locating the cid of the runner through the `get_local_cid` does give the same result.
        // When PLAT-288 lands, the cid may also here be retrieved through the open runner-enclave
        // connection
        let runner_cid = vsock::get_local_cid().unwrap_or(VMADDR_CID_LOCAL);
        let runner = VsockAddr::new(runner_cid, runner_port);
        let k = ConnectionKey::from_addresses(enclave, runner);
        self.connections.read().await.get(&k).cloned()
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
    async fn handle_request_bind(
        self: &Self,
        addr: &String,
        enclave_port: u32,
        conn: &mut ClientConnection,
    ) -> Result<(), VmeError> {
        let cid: u32 = conn.stream.peer_addr()?.cid();
        let mut local_addr_str = String::new();
        let listener = self
            .stream_router
            .bind_stream(addr, Some(&mut local_addr_str))
            .await
            .map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string(&local_addr_str);
        self.add_listener(
            VsockAddr::new(cid, enclave_port),
            Listener::new(listener, local.clone()),
        )
        .await;
        conn.send(&Response::Bound { local }).await?;
        Ok(())
    }

    async fn handle_request_accept(
        self: &Self,
        vsock_listener_port: u32,
        client_conn: &mut ClientConnection,
    ) -> Result<(), VmeError> {
        use nix::{errno::Errno, sys::socket};

        fn nix_to_vme_error(errno: Errno) -> VmeError {
            VmeError::SystemError(errno as i32)
        }

        fn vsock_create_bind(
            runner_port: u32,
            runner_cid: u32,
        ) -> Result<vsock::VsockStream, VmeError> {
            let socket = unsafe {
                use std::os::fd::{FromRawFd, IntoRawFd};
                let socket = socket::socket(
                    socket::AddressFamily::Vsock,
                    socket::SockType::Stream,
                    socket::SockFlag::SOCK_CLOEXEC | socket::SockFlag::SOCK_NONBLOCK,
                    None,
                )
                .map_err(nix_to_vme_error)?;
                vsock::VsockStream::from_raw_fd(socket.into_raw_fd())
            };

            let runner_addr = socket::VsockAddr::new(runner_cid, runner_port);
            socket::bind(socket.as_raw_fd(), &runner_addr).map_err(nix_to_vme_error)?;

            Ok(socket)
        }

        async fn vsock_connect(
            socket: vsock::VsockStream,
            enclave_cid: u32,
            enclave_port: u32,
        ) -> Result<VsockStream, VmeError> {
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

        let listener = self.listener(&enclave_addr).await.ok_or(IoError::new(
            IoErrorKind::InvalidInput,
            "Information about provided file descriptor was not found",
        ))?;

        // Accept connection for listener
        let mut listener = listener.lock().await;
        let mut local_addr_str = String::new();
        let mut peer_addr_str = String::new();
        let conn = accept_stream(
            &mut listener.listener,
            Some(&mut local_addr_str),
            Some(&mut peer_addr_str),
        )
        .await
        .map_err(|e| VmeError::Command(e.kind().into()))?;
        let local = addr_from_string(&local_addr_str);
        let peer = addr_from_string(&peer_addr_str);
        drop(listener);

        // Send enclave info where it should accept new incoming connection
        let runner_vsock_socket = vsock_create_bind(VMADDR_PORT_ANY, VMADDR_CID_ANY)?;
        let runner_port = runner_vsock_socket.local_addr()?.port();
        client_conn
            .send(&Response::IncomingConnection {
                local: local.clone(),
                peer: peer.clone(),
                proxy_port: runner_port,
            })
            .await?;

        let connect = async {
            // Connect to enclave at the expected port
            let proxy =
                vsock_connect(runner_vsock_socket, enclave_cid, vsock_listener_port).await?;
            self.add_connection(
                proxy,
                conn,
                "remote".to_string(),
                ConnectionInfo { local, peer },
            )
            .await?;
            Ok::<(), VmeError>(())
        };
        if let Err(e) = connect.await {
            error!(
                "Failed to connect to the enclave after it requested an accept: {:?}",
                e
            );
        }
        Ok(())
    }

    async fn handle_request_close(
        self: &Self,
        enclave_port: u32,
        conn: &mut ClientConnection,
    ) -> Result<(), VmeError> {
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

    async fn handle_request_info(
        self: &Self,
        enclave_port: u32,
        runner_port: Option<u32>,
        conn: &mut ClientConnection,
    ) -> Result<(), VmeError> {
        let enclave_cid = conn.peer_port()?;
        let enclave_addr = VsockAddr::new(enclave_cid, enclave_port);
        if let Some(runner_port) = runner_port {
            // We're looking for a Connection
            if let Some(ConnectionInfo { local, peer }) =
                self.connection_info(enclave_addr, runner_port).await
            {
                conn.send(&Response::Info {
                    local,
                    peer: Some(peer),
                })
                .await?;
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
                })
                .await?;
                Ok(())
            } else {
                // Listener not found
                Err(VmeError::ConnectionNotFound)
            }
        }
    }

    fn handle_request_exit(self: &Self, exit_code: i32) -> Result<(), VmeError> {
        if self.forward_panics && exit_code != 0 {
            panic!("enclave panicked with exit code: {}", exit_code);
        } else {
            std::process::exit(exit_code);
        }
    }

    async fn handle_client(self: &Self, conn: &mut ClientConnection) -> Result<(), VmeError> {
        match conn.read_request().await.or_else(|e| {
            error!("read_request error: {:?}", e);
            Err(e)
        })? {
            Request::Init => self.handle_request_init(conn).await.or_else(|e| {
                error!("init error: {:?}", e);
                Err(e)
            }),
            Request::Connect { addr } => {
                self.handle_request_connect(&addr, conn).await.or_else(|e| {
                    error!("connect error: {:?}", e);
                    Err(e)
                })
            }
            Request::Bind { addr, enclave_port } => self
                .handle_request_bind(&addr, enclave_port, conn)
                .await
                .or_else(|e| {
                    error!("bind error: {:?}", e);
                    Err(e)
                }),
            Request::Accept { enclave_port } => self
                .handle_request_accept(enclave_port, conn)
                .await
                .or_else(|e| {
                    error!("accept error: {:?}", e);
                    Err(e)
                }),
            Request::Info {
                enclave_port,
                runner_port,
            } => self
                .handle_request_info(enclave_port, runner_port, conn)
                .await
                .or_else(|e| {
                    error!("info error: {:?}", e);
                    Err(e)
                }),
            Request::Close { enclave_port } => self
                .handle_request_close(enclave_port, conn)
                .await
                .or_else(|e| {
                    error!("close error: {:?}", e);
                    Err(e)
                }),
            Request::Exit { code } => self.handle_request_exit(code).or_else(|e| {
                error!("exit error: {:?}", e);
                Err(e)
            }),
        }
    }
}

async fn accept_stream(
    listener: &mut Pin<Box<dyn AsyncListener>>,
    mut local_addr: Option<&mut String>,
    mut peer_addr: Option<&mut String>,
) -> io::Result<Box<dyn AsyncStream>> {
    poll_fn(|cx| {
        listener
            .as_mut()
            .poll_accept(cx, local_addr.as_deref_mut(), peer_addr.as_deref_mut())
    })
    .await
}

/// An type that implements [`enclave_runner::EnclavePlatform<enclave_runner::Command>`]. So user
/// can use enclave_runner API to create vme enclaves.
///
/// ```ignore
/// let run_args = NitroRunArgs { ... };
/// let enclave_args = vec!["--arg1", "foo"];
/// let enclave_runner = EnclaveBuilder::<NitroEnclaves, _>::new(run_args, "enclave_name")?;
/// let mut enclave_runner = enclave_runner::EnclaveBuilder::new(enclave_runner);
/// enclave_runner.args(enclave_args);
/// let enclave = enclave_runner.build(()).expect("Failed to build enclave runner");
/// enclave.run().expect("Failed to run enclave");
/// ```
pub struct EnclaveBuilder<P: Platform, Args: Into<P::RunArgs>> {
    platform: PhantomData<P>,
    runner_args: Args,
    enclave_name: String,
}

impl<P: Platform + 'static, Args: Into<P::RunArgs> + Send + 'static> EnclaveBuilder<P, Args> {
    pub fn new(runner_args: Args, enclave_name: String) -> Result<Self, anyhow::Error> {
        Ok(Self {
            platform: PhantomData,
            runner_args,
            enclave_name,
        })
    }

    pub async fn start_server_and_run_enclave(
        self,
        mut enclave_args: Vec<String>,
        stream_router: BoxedStreamRouter,
        forward_panics: bool,
    ) -> Result<(), RunnerError> {
        let EnclaveBuilder {
            runner_args,
            enclave_name,
            ..
        } = self;

        enclave_args.insert(0, enclave_name);

        let command_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, SERVER_PORT))?;
        let command_listener_local_addr = command_listener.local_addr()?;

        let state = Arc::new(ServerState {
            forward_panics,
            enclave_args,
            command_listener,
            stream_router,
            listeners: RwLock::new(FnvHashMap::default()),
            connections: Arc::new(RwLock::new(FnvHashMap::default())),
        });

        info!("Starting enclave runner.");
        info!(
            "Command server listening on vsock cid: {} port: {} ...",
            command_listener_local_addr.cid(),
            command_listener_local_addr.port()
        );
        // This line is critical to ensure state keeps live otherwise it's moved into the future
        let command_server_state = state.clone();
        let command_server_handle = tokio::spawn(async move {
            loop {
                let state_for_conn = command_server_state.clone();
                let accepted = command_server_state.command_listener.accept().await;
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
        });

        let _enclave_descriptor = tokio::task::spawn_blocking(|| P::run(runner_args)).await??;
        command_server_handle.await?;

        Ok(())
    }
}

impl<P: Platform + 'static, Args: Into<P::RunArgs> + 'static + Send>
    EnclavePlatform<enclave_runner::Command> for EnclaveBuilder<P, Args>
{
    type Loader = ();

    fn build(
        self,
        _loader: Self::Loader,
        configuration: EnclaveConfiguration,
        mut cmd_configuration: CommandConfiguration,
    ) -> Result<enclave_runner::Command, anyhow::Error> {
        // By default: cmd_args[0] == "enclave", where `enclave` is process name.
        // In VME runner we will use inject image name at index 0 as process name, so remove it here.
        cmd_configuration.cmd_args.remove(0);
        Ok(command::internal_new(
            self,
            configuration.stream_router,
            configuration.forward_panics,
            cmd_configuration,
        ))
    }
}

/// Module of helper functions for implementing [`enclave_runner`] traits.
mod command {
    use super::*;
    use enclave_runner::stream_router::StreamRouter;

    pub(crate) fn internal_new<P: Platform + 'static, Args: Into<P::RunArgs> + 'static + Send>(
        enclave_builder: EnclaveBuilder<P, Args>,
        stream_router: Box<dyn StreamRouter + Send + Sync>,
        forward_panics: bool,
        cmd_configuration: CommandConfiguration,
    ) -> enclave_runner::Command {
        (Box::new(move || -> Result<(), anyhow::Error> {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let enclave_args = cmd_configuration
                        .cmd_args
                        .into_iter()
                        .map(|arr| String::from_utf8(arr))
                        .collect::<Result<Vec<_>, _>>()?;
                    enclave_builder
                        .start_server_and_run_enclave(enclave_args, stream_router, forward_panics)
                        .await?;
                    Ok(())
                })
        }) as Box<dyn FnOnce() -> _>)
            .into()
    }
}
