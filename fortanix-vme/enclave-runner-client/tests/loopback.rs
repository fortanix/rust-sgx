//! `Client` against a fake runner over vsock loopback (CID 1).
//!
//! Needs the `vsock_loopback` kernel module, so every test is ignored by default.
//! Run them in both builds of the client:
//!
//!     sudo modprobe vsock_loopback
//!     cargo test -p enclave-runner-client --test loopback -- --ignored
//!     cargo test -p enclave-runner-client --no-default-features --features alloc --test loopback -- --ignored
//!
//! The fake runner only uses vsock APIs that exist without vsock's `std` feature,
//! so this file compiles in both builds. Each fake runner listens on a random
//! port, so the tests can run in parallel. `Client::exit` is not tested here: it
//! calls `libc::exit`, which would end the test process.

use std::thread::{self, JoinHandle};
use std::time::Duration;

use enclave_runner_client::{Client, ConnectionInfo, Error};
use fortanix_vme_abi::{Addr, Error as RunnerError, ErrorKind, Request, Response};
use vsock::{Platform, VsockListener, VsockStream, VMADDR_CID_LOCAL};

/// Upper bound on how long the fake runner waits for the client.
const TIMEOUT: Duration = Duration::from_secs(10);

/// `vsock::Platform` for the fake runner. This test crate always has std, but
/// it shares one build of `vsock` with the client, and in the client's no-std
/// build that `vsock` is compiled without its `std` feature, so the ready-made
/// `vsock::Std` platform doesn't exist. This does the same thing.
struct TestPlatform;

impl Platform for TestPlatform {
    fn last_os_error() -> vsock::Error {
        vsock::Error::SystemError(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

type Stream = VsockStream<TestPlatform>;
type Listener = VsockListener<TestPlatform>;

/// The runner's side of one command connection.
struct RunnerConn(Stream);

impl RunnerConn {
    fn read_request(&mut self) -> Request {
        let mut len = [0u8; size_of::<usize>()];
        self.0.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; usize::from_le_bytes(len)];
        self.0.read_exact(&mut body).unwrap();
        serde_cbor::from_slice(&body).unwrap()
    }

    fn send(&mut self, resp: &Response) {
        let body = serde_cbor::ser::to_vec(resp).unwrap();
        self.0.write_all(&body.len().to_le_bytes()).unwrap();
        self.0.write_all(&body).unwrap();
    }
}

/// Starts a fake runner on a random vsock port. It accepts one command
/// connection and runs `script` on it. Returns the port, and the thread:
/// joining it re-raises any assertion that failed inside the script.
fn fake_runner<R, F>(script: F) -> (u32, JoinHandle<R>)
where
    F: FnOnce(&mut RunnerConn) -> R + Send + 'static,
    R: Send + 'static,
{
    let listener = Listener::bind_with_cid(VMADDR_CID_LOCAL)
        .expect("cannot bind on vsock CID 1: is vsock_loopback loaded?");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        script(&mut RunnerConn(stream))
    });
    (port, handle)
}

/// Accepts one connection on a raw listener fd returned by the client.
fn accept_on_fd(fd: i32) -> Stream {
    let conn = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert!(conn >= 0, "accept failed: {}", std::io::Error::last_os_error());
    unsafe { Stream::from_raw_fd(conn) }
}

/// Built by hand: `From<SocketAddr> for Addr` needs fortanix-vme-abi's `core`
/// or `std` feature, which the client's no-std build doesn't enable.
fn ipv4(ip: [u8; 4], port: u16) -> Addr {
    Addr::IPv4 { ip, port }
}

// Requests that succeed

#[test]
#[ignore = "needs vsock_loopback"]
fn args_returns_runner_args() {
    let (port, runner) = fake_runner(|conn| {
        assert_eq!(conn.read_request(), Request::Init);
        conn.send(&Response::Init { args: vec!["enclave".into(), "--flag".into()] });
    });

    assert_eq!(Client::args(Some(port)).unwrap(), ["enclave", "--flag"]);
    runner.join().unwrap();
}

#[test]
#[ignore = "needs vsock_loopback"]
fn close_connection_sends_close() {
    let (port, runner) = fake_runner(|conn| {
        assert_eq!(conn.read_request(), Request::Close { enclave_port: 42 });
        conn.send(&Response::Closed);
    });

    Client::close_connection(Some(port), 42).unwrap();
    runner.join().unwrap();
}

#[test]
#[ignore = "needs vsock_loopback"]
fn open_proxy_connection_connects_to_proxy() {
    let (port, runner) = fake_runner(|conn| {
        assert_eq!(conn.read_request(), Request::Connect { addr: "example.com:80".into() });
        let proxy = Listener::bind_with_cid(VMADDR_CID_LOCAL).unwrap();
        conn.send(&Response::Connected {
            proxy_port: proxy.local_addr().unwrap().port(),
            local: ipv4([10, 0, 0, 2], 5000),
            peer: ipv4([93, 184, 216, 34], 80),
        });

        // The client now connects to the proxy port. Echo what it sends.
        let (stream, enclave_addr) = proxy.accept().unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        stream.write_all(&buf).unwrap();
        enclave_addr.port()
    });

    let mut client = Client::new(Some(port)).unwrap();
    let info = client.open_proxy_connection("example.com:80".into()).unwrap();
    let (enclave_port, local, peer, fd) = match info {
        ConnectionInfo::Stream { enclave_port, local, peer, fd } => (enclave_port, local, peer, fd),
        other => panic!("expected a stream, got {:?}", other),
    };
    assert_eq!(local, ipv4([10, 0, 0, 2], 5000));
    assert_eq!(peer, ipv4([93, 184, 216, 34], 80));

    // The returned fd is the client's end of the proxy connection.
    let proxy = unsafe { Stream::from_raw_fd(fd.expect("stream fd")) };
    proxy.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    proxy.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    assert_eq!(runner.join().unwrap(), enclave_port, "enclave_port must be the client's port");
}

#[test]
#[ignore = "needs vsock_loopback"]
fn bind_socket_then_accept() {
    let (port, runner) = fake_runner(|conn| {
        let enclave_port = match conn.read_request() {
            Request::Bind { addr, enclave_port } if addr == "0.0.0.0:8080" => enclave_port,
            other => panic!("expected Bind for 0.0.0.0:8080, got {:?}", other),
        };
        conn.send(&Response::Bound { local: ipv4([0, 0, 0, 0], 8080) });

        // Like the real runner: reply first, then connect to the enclave's listener.
        assert_eq!(conn.read_request(), Request::Accept { enclave_port });
        conn.send(&Response::IncomingConnection {
            local: ipv4([10, 0, 0, 2], 8080),
            peer: ipv4([10, 0, 0, 9], 40000),
            proxy_port: 7777,
        });
        let incoming = Stream::connect_with_cid_port(VMADDR_CID_LOCAL, enclave_port).unwrap();
        incoming.write_all(b"hello").unwrap();
    });

    let mut client = Client::new(Some(port)).unwrap();
    let info = client.bind_socket("0.0.0.0:8080".into()).unwrap();
    let (local, enclave_port, fd) = match info {
        ConnectionInfo::Listener { local, enclave_port, fd } => (local, enclave_port, fd),
        other => panic!("expected a listener, got {:?}", other),
    };
    assert_eq!(local, ipv4([0, 0, 0, 0], 8080));

    let (local, peer, proxy_port) = client.accept(enclave_port).unwrap();
    assert_eq!(local, ipv4([10, 0, 0, 2], 8080));
    assert_eq!(peer, ipv4([10, 0, 0, 9], 40000));
    assert_eq!(proxy_port, 7777);

    // The returned fd is a real listener: the runner's connection arrives on it.
    let stream = accept_on_fd(fd.expect("listener fd"));
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");

    runner.join().unwrap();
}

// Failures

#[test]
#[ignore = "needs vsock_loopback"]
fn no_runner_reports_errno() {
    // Bind and drop a listener to get a port nobody listens on.
    let port = Listener::bind_with_cid(VMADDR_CID_LOCAL).unwrap().local_addr().unwrap().port();

    // A real errno (> 0) shows that `ClientPlatform` reads errno correctly. In the
    // no-std build, that is the `libc::__errno_location` path.
    match Client::new(Some(port)) {
        Err(Error::SystemError(errno)) if errno > 0 => {}
        other => panic!("expected SystemError(errno > 0), got {:?}", other.err()),
    }
}

#[test]
#[ignore = "needs vsock_loopback"]
fn runner_command_error_is_returned() {
    let (port, runner) = fake_runner(|conn| {
        conn.read_request();
        conn.send(&Response::Failed(RunnerError::Command(ErrorKind::ConnectionRefused)));
    });

    let mut client = Client::new(Some(port)).unwrap();
    let err = client.open_proxy_connection("example.com:80".into()).unwrap_err();
    assert_eq!(err, Error::IoError(ErrorKind::ConnectionRefused));
    runner.join().unwrap();
}

#[test]
#[ignore = "needs vsock_loopback"]
fn connection_not_found_is_an_error() {
    let (port, runner) = fake_runner(|conn| {
        conn.read_request();
        conn.send(&Response::Failed(RunnerError::ConnectionNotFound));
    });

    let result = Client::close_connection(Some(port), 42);
    assert!(matches!(result, Err(Error::Other(_))), "got {:?}", result);
    runner.join().unwrap();
}

#[test]
#[ignore = "needs vsock_loopback"]
fn wrong_reply_is_invalid_data() {
    let (port, runner) = fake_runner(|conn| {
        assert_eq!(conn.read_request(), Request::Init);
        conn.send(&Response::Closed);
    });

    assert_eq!(Client::args(Some(port)), Err(Error::IoError(ErrorKind::InvalidData)));
    runner.join().unwrap();
}

#[test]
#[ignore = "needs vsock_loopback"]
fn runner_hanging_up_mid_reply_is_unexpected_eof() {
    let (port, runner) = fake_runner(|conn| {
        conn.read_request();
        // Announce a 100-byte body, then close the connection.
        conn.0.write_all(&100usize.to_le_bytes()).unwrap();
    });

    assert_eq!(Client::args(Some(port)), Err(Error::IoError(ErrorKind::UnexpectedEof)));
    runner.join().unwrap();
}
