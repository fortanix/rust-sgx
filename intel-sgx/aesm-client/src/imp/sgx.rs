use std::net::TcpStream;
pub use error::Result;
mod aesm_protobuf;

#[derive(Debug)]
pub struct AesmClient {
    tcp_stream: TcpStream,
}

impl Clone for AesmClient {
    fn clone(&self) -> Self {
        AesmClient {
            tcp_stream: self.tcp_stream.try_clone().unwrap()
        }
    }
}

impl AesmClient {
    fn open_socket(&self) -> Result<TcpStream> {
        let sock = self.tcp_stream.try_clone().unwrap();
        // FIXME: uncomment this after resolving https://github.com/fortanix/rust-sgx/issues/31
        // let _ = sock.set_write_timeout(Some(Duration::from_micros(LOCAL_AESM_TIMEOUT_US as _)))?;
        Ok(sock)
    }
}

impl crate::sgx::AesmClientExt for crate::AesmClient {
    fn new(tcp_stream: TcpStream) -> Self {
        crate::AesmClient {
            inner: self::AesmClient {
                tcp_stream
            }
        }
    }
}
