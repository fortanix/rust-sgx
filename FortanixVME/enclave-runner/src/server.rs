use nix::sys::select::{select, FdSet};
use std::thread::{self, JoinHandle};
use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Read, Write};
use std::marker::PhantomData;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use fortanix_vme_abi::{self, Error, Response, Request};
use vsock::{SockAddr, VsockListener, VsockStream};

const BUFF_SIZE: usize = 1024;
const PROXY_BUFF_SIZE: usize = 4192;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

pub struct Server<T: ProxyConnection> {
    port: Option<u16>,
    phantom_data: PhantomData<T>
}

pub trait ProxyConnection {
    type Listener: StreamListener;
    type Stream: StreamConnection;

    fn name() -> &'static str;

    fn bind(port: Option<u16>) -> io::Result<Self::Listener>;

    fn incoming(listener: &Self::Listener) -> io::Result<Self::Stream>;
}

pub trait StreamConnection: Read + Write + Sized + Send + 'static {
    fn local(&self) -> io::Result<String>;

    fn local_port(&self) -> io::Result<u32>;

    fn peer(&self) -> io::Result<String>;

    fn peer_port(&self) -> io::Result<u32>;

    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
}

pub trait StreamListener: Send + 'static {
    fn port(&self) -> io::Result<u32>;
}

pub struct Tcp {}

impl ProxyConnection for Tcp {
    type Listener = TcpListener;
    type Stream = TcpStream;

    fn name() -> &'static str {
        "TCP"
    }

    fn bind(port: Option<u16>) -> io::Result<Self::Listener> {
        TcpListener::bind(format!("127.0.0.1:{}", port.unwrap_or(0)))
    }

    fn incoming(listener: &Self::Listener) -> io::Result<Self::Stream> {
        listener.accept().map(|(stream, _addr)| stream)
    }
}

impl StreamConnection for TcpStream {
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

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl StreamListener for TcpListener {
    fn port(&self) -> io::Result<u32> {
        self.local_addr().map(|addr| addr.port() as _)
    }
}

pub struct Vsock {}

impl ProxyConnection for Vsock {
    fn name() -> &'static str {
        "Vsock"
    }

    type Listener = VsockListener;
    type Stream = VsockStream;

    fn bind(port: Option<u16>) -> io::Result<Self::Listener> {
        VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port.unwrap_or(0) as _)
    }

    fn incoming(listener: &Self::Listener) -> io::Result<Self::Stream> {
        listener.accept().map(|(stream, _addr)| stream)
    }
}

impl StreamConnection for VsockStream {
    fn local(&self) -> io::Result<String> {
        self.local_addr().map(|addr| if let SockAddr::Vsock(addr) = addr {
            format!("{}", addr.cid())
        } else {
            unreachable!();
        })
    }

    fn local_port(&self) -> io::Result<u32> {
        self.local_addr().map(|addr| if let SockAddr::Vsock(addr) = addr {
            addr.port()
        } else {
            unreachable!();
        })
    }

    fn peer(&self) -> io::Result<String> {
        self.peer_addr().map(|addr| if let SockAddr::Vsock(addr) = addr {
            format!("{}", addr.cid())
        } else {
            unreachable!();
        })
    }

    fn peer_port(&self) -> io::Result<u32> {
        self.peer_addr().map(|addr| if let SockAddr::Vsock(addr) = addr {
            addr.port()
        } else {
            unreachable!();
        })
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl StreamListener for VsockListener {
    fn port(&self) -> io::Result<u32> {
        self.local_addr().map(|addr| if let SockAddr::Vsock(addr) = addr {
            addr.port() as _
        } else {
            0
        })
    }
}

impl<T: ProxyConnection> Server<T> {
    pub fn new(port: Option<u16>) -> Self {
        Server {
            port,
            phantom_data: PhantomData::default(),
        }
    }

    fn read_from_stream(stream: &mut T::Stream) -> Result<Vec<u8>, IoError> {
        let mut buff = [0; BUFF_SIZE];
        let n = stream.read(&mut buff)?;
        let mut buff = buff[0..n].to_vec();
        //TODO This will block when the n*BUFF_SIZE bytes need to be read
        if n == BUFF_SIZE {
            buff.append(&mut Self::read_from_stream(stream)?);
        }
        Ok(buff)
    }

    fn log_communication(src: &str, src_port: u32, dst: &str, dst_port: u32, msg: &str, arrow: &str) {
        let src = format!("{}:{}", src, src_port);
        let dst = format!("{}:{}", dst, dst_port);
        let msg: String = msg.chars().into_iter().take(80).collect();
        println!("{:>20} {} {:<20}: {:?}", src, arrow, dst, msg);
    }

    fn read_request(stream: &mut T::Stream) -> Result<Request, Error> {
        let buff = Self::read_from_stream(stream)?;
        let req = serde_cbor::from_slice(&buff).map_err(|e| Error::DeserializationError(e))?;
        Self::log_communication(
            "runner",
            stream.local_port().unwrap_or_default(),
            "enclave",
            stream.peer_port().unwrap_or_default(),
            &format!("{:?}", &req),
            "<-");
        Ok(req)
    }

    fn transfer_data(src: &mut TcpStream, src_name: &str, dst: &mut TcpStream, dst_name: &str) -> Result<usize, IoError> {
        let mut buff = [0; PROXY_BUFF_SIZE];
        let n = src.read(&mut buff[..])?;
        Self::log_communication(
            "runner",
            src.local_addr().map(|addr| addr.port() as _).unwrap_or_default(),
            src_name,
            src.peer_addr().map(|addr| addr.port() as _).unwrap_or_default(),
            &String::from_utf8(buff[0..n].to_vec()).unwrap_or_default(),
            "<-");
        if n > 0 {
            dst.write_all(&buff[0..n])?;
            Self::log_communication(
                dst_name,
                dst.peer_addr().map(|addr| addr.port() as _).unwrap_or_default(),
                "runner",
                dst.local_addr().map(|addr| addr.port() as _).unwrap_or_default(),
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
    fn handle_request_connect(remote_addr: &String, enclave: &mut T::Stream) -> Result<(), IoError> {
        // Connect to remote server
        let mut remote_socket = TcpStream::connect(remote_addr)?;
        let remote_name = remote_addr.split_terminator(":").next().unwrap_or(remote_addr);

        // Create listening socket that the enclave can connect to
        let proxy_server = TcpListener::bind("127.0.0.1:0")?;
        let proxy_server_port = proxy_server.local_addr()?.port();

        // Notify the enclave on which port her proxy is listening on
        let response = Response::Connected {
                port: proxy_server_port,
                local_addr: enclave.local()?,
                peer_addr: enclave.peer()?,
            };
        Self::log_communication(
            "runner",
            enclave.local_port().unwrap_or_default(),
            "enclave",
            enclave.peer_port().unwrap_or_default(),
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

    fn handle_client(stream: &mut T::Stream) -> Result<(), IoError> {
        match Self::read_request(stream) {
            Ok(Request::Connect{ addr }) => Self::handle_request_connect(&addr, stream)?,
            Err(_e)                      => return Err(IoError::new(IoErrorKind::InvalidInput, "Failed to read request")),
        };
        Ok(())
    }

    pub fn run(&self) -> std::io::Result<(JoinHandle<()>, u32)> {
        println!("Starting enclave runner.");
        let listener = T::bind(self.port)?;
        let port = listener.port()?;
        println!("Listening on {} port {}...", T::name(), port);

        let handle = thread::Builder::new().spawn(move || {
            let listener = listener;
            loop {
                let stream = T::incoming(&listener).unwrap();
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

