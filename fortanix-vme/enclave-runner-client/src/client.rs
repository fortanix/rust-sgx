// std types are just re-exports of alloc/core types. Conditional compilation is not necessary here,
// and it allows clean compilation even with no features enabled.
use {
    alloc::string::String,
    alloc::vec::Vec,
};
use fortanix_vme_abi::{self, ErrorKind, Request, Response, Addr};
use vsock::{VsockStream, VsockListener, SockAddr};

use crate::Error;
use crate::connection_info::ConnectionInfo;
use crate::fortanixvme::Fortanixvme;

pub struct Client {
    stream: VsockStream<Fortanixvme>,
}

impl Client {
    fn connect(port: u32) -> Result<VsockStream<Fortanixvme>, Error> {
        // Try to contact the enclave runner through the hypervisor
        VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, port).or_else(|e0| {
            // When debugging, there may not be a hypervisor. Fall back to local communication
            // on the same host.
            VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)
                .map_err(|_e1| Error::from(e0))
        })
    }

    pub fn new(port: Option<u32>) -> Result<Self, Error> {
        let port = port.unwrap_or(fortanix_vme_abi::SERVER_PORT);
        Ok(Client { stream: Self::connect(port)? })
    }

    pub fn open_proxy_connection(&mut self, addr: String) -> Result<ConnectionInfo, Error> {
        let connect = Request::Connect { addr };
        self.send(&connect)?;
        if let Response::Connected { proxy_port, local, peer } = self.receive()? {
            let proxy = Self::connect(proxy_port)?;
            let enclave_port = proxy.local_addr()?.port();

            Ok(ConnectionInfo::new_stream_info(
                enclave_port,
                local,
                peer,
                Some(proxy.into_raw_fd())
            ))
        } else {
            Err(Error::IoError(ErrorKind::InvalidData))
        }
    }

    /// Bind a TCP socket in the parent VM to the specified address. Returns a Socket
    /// listening for incoming connections forwarded by the parent VM
    pub fn bind_socket(&mut self, addr: String) -> Result<ConnectionInfo, Error> {
        // Start listener socket within enclave, waiting for incoming connections from enclave
        // runner
        let listener = VsockListener::<Fortanixvme>::bind_with_cid(vsock::VMADDR_CID_ANY)?;
        let enclave_port = listener.local_addr()?.port();

        // Tell runner to start listening on the specified address and forward trafic to the
        // specified port
        let bind = Request::Bind { addr, enclave_port };
        self.send(&bind)?;
        if let Response::Bound { local } = self.receive()? {
            Ok(ConnectionInfo::new_listener_info(
                local,
                enclave_port,
                Some(listener.into_raw_fd())
            ))
        } else {
            Err(Error::IoError(ErrorKind::InvalidData))
        }
    }

    pub fn accept(&mut self, vsock_port: u32) -> Result<(Addr, Addr, u32), Error> {
        let accept = Request::Accept { enclave_port: vsock_port };
        self.send(&accept)?;

        if let Response::IncomingConnection { local, peer, proxy_port } = self.receive()? {
            Ok((local, peer, proxy_port))
        } else {
            Err(Error::IoError(ErrorKind::InvalidData))
        }
    }

    pub fn close_connection(port: Option<u32>, enclave_port: u32) -> Result<(), Error> {
        let mut client = Self::new(port)?;

        let close = Request::Close { enclave_port };
        client.send(&close)?;

        if let Response::Closed = client.receive()? {
            Ok(())
        } else {
            Err(Error::IoError(ErrorKind::InvalidData))
        }
    }

    pub fn args(port: Option<u32>) -> Result<Vec<String>, Error> {
        let mut client = Self::new(port)?;
        client.send(&Request::Init)?;
        let r = client.receive()?;
        if let Response::Init { args } = r {
            Ok(args)
        } else {
            Err(Error::IoError(ErrorKind::InvalidData))
        }
    }

    pub fn exit(port: Option<u32>, code: i32) -> ! {
        let _ = Self::new(port)
            .and_then(|mut client| client.send(&Request::Exit { code }));

        // Failed to connect to the runner, stop the enclave anyway
        unsafe { libc::exit(code as libc::c_int) }
    }

    pub fn local_vsock_addr(fd: i32) -> Result<SockAddr, Error> {
        Ok(SockAddr::from_raw_fd::<Fortanixvme>(fd)?)
    }

    fn send(&mut self, req: &Request) -> Result<(), Error> {
        let req: Vec<u8> = serde_cbor::ser::to_vec(req)
            .map_err(|_e| Error::SerializationError)?;
        self.stream.write_all(&req.len().to_le_bytes())?;
        self.stream.write_all(req.as_slice())?;
        Ok(())
    }

    fn receive(&mut self) -> Result<Response, Error> {
        let mut size = [0u8; usize::BITS as usize / 8];
        self.stream.read_exact(&mut size[..])?;
        let size = usize::from_le_bytes(size);

        let mut resp = Vec::new();
        resp.resize(size, 0);
        self.stream.read_exact(&mut resp[..])?;
        let resp = serde_cbor::from_slice(&resp)
            .map_err(|_| Error::DeserializationError)?;

        match resp {
            fortanix_vme_abi::Response::Failed(fortanix_vme_abi::Error::Command(kind)) => {
                Err(Error::IoError(kind))
            }
            fortanix_vme_abi::Response::Failed(fortanix_vme_abi::Error::SystemError(errno)) => {
                Err(Error::SystemError(errno))
            }
            other => Ok(other),
        }
    }
}