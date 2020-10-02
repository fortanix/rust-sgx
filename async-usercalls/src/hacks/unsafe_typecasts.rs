//! The incredibly unsafe code in this module allows us to create
//! `std::net::TcpStream` and `std::net::TcpListener` types from their raw
//! components in SGX.
//!
//! This is obviously very unsafe and not maintainable and is only intended as
//! an iterim solution until we add similar functionality as extension traits
//! in `std::os::fortanix_sgx`.
use fortanix_sgx_abi::Fd;

mod sgx {
    use fortanix_sgx_abi::Fd;
    use std::sync::Arc;

    #[derive(Debug)]
    pub struct FileDesc {
        fd: Fd,
    }

    #[derive(Debug, Clone)]
    pub struct Socket {
        inner: Arc<FileDesc>,
        local_addr: Option<String>,
    }

    #[derive(Clone)]
    pub struct TcpStream {
        inner: Socket,
        peer_addr: Option<String>,
    }

    impl TcpStream {
        pub fn new(fd: Fd, local_addr: Option<String>, peer_addr: Option<String>) -> TcpStream {
            TcpStream {
                inner: Socket {
                    inner: Arc::new(FileDesc { fd }),
                    local_addr,
                },
                peer_addr,
            }
        }
    }

    #[derive(Clone)]
    pub struct TcpListener {
        inner: Socket,
    }

    impl TcpListener {
        pub fn new(fd: Fd, local_addr: Option<String>) -> TcpListener {
            TcpListener {
                inner: Socket {
                    inner: Arc::new(FileDesc { fd }),
                    local_addr,
                },
            }
        }
    }
}

struct TcpStream(self::sgx::TcpStream);
struct TcpListener(self::sgx::TcpListener);

pub unsafe fn new_std_stream(fd: Fd, local_addr: Option<String>, peer_addr: Option<String>) -> std::net::TcpStream {
    let stream = TcpStream(sgx::TcpStream::new(fd, local_addr, peer_addr));
    std::mem::transmute(stream)
}

pub unsafe fn new_std_listener(fd: Fd, local_addr: Option<String>) -> std::net::TcpListener {
    let listener = TcpListener(sgx::TcpListener::new(fd, local_addr));
    std::mem::transmute(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    use std::os::fortanix_sgx::io::AsRawFd;

    #[test]
    fn sanity_check() {
        let fd = 42;
        let local = "1.2.3.4:1234";
        let peer = "5.6.7.8:443";
        let stream = unsafe { new_std_stream(fd, Some(local.to_owned()), Some(peer.to_owned())) };
        assert_eq!(stream.as_raw_fd(), fd);
        assert_eq!(stream.local_addr().unwrap().to_string(), local);
        assert_eq!(stream.peer_addr().unwrap().to_string(), peer);
        mem::forget(stream); // not a real stream...

        let listener = unsafe { new_std_listener(fd, Some(local.to_owned())) };
        assert_eq!(listener.as_raw_fd(), fd);
        assert_eq!(listener.local_addr().unwrap().to_string(), local);
        mem::forget(listener); // not a real listener...
    }
}
