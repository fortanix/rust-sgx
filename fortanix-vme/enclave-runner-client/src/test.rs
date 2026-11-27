//! Framing and error mapping, tested with an in-memory stand-in for
//! the vsock stream. No sockets needed.

mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use fortanix_vme_abi::{Addr, Error as RunnerError, ErrorKind, Request, Response};

    use crate::client::{receive_response, send_request, Transport};
    use crate::{ConnectionInfo, Error};

    /// In-memory stand-in for the vsock stream: records what the client writes
    /// and serves `input` as the runner's replies.
    #[derive(Default)]
    struct Mock {
        written: Vec<u8>,
        input: Vec<u8>,
        pos: usize,
    }

    impl Mock {
        fn replying(input: Vec<u8>) -> Self {
            Mock { input, ..Default::default() }
        }
    }

    impl Transport for Mock {
        fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
            self.written.extend_from_slice(buf);
            Ok(())
        }

        fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
            let end = self.pos + buf.len();
            // Same error the real stream gives when the runner hangs up.
            let src = self
                .input
                .get(self.pos..end)
                .ok_or(Error::IoError(ErrorKind::UnexpectedEof))?;
            buf.copy_from_slice(src);
            self.pos = end;
            Ok(())
        }
    }

    /// Frames a message the way the runner does (`ClientConnection::send` in
    /// fortanix-vme-runner): body length as a little-endian `usize`, then the body.
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut frame = body.len().to_le_bytes().to_vec();
        frame.extend_from_slice(body);
        frame
    }

    fn runner_reply(resp: &Response) -> Vec<u8> {
        frame(&serde_cbor::ser::to_vec(resp).unwrap())
    }

    fn receive(input: Vec<u8>) -> Result<Response, Error> {
        receive_response(&mut Mock::replying(input))
    }

    // send_request

    #[test]
    fn send_writes_length_then_cbor() {
        let req = Request::Bind { addr: "0.0.0.0:8080".to_string(), enclave_port: 1234 };
        let mut mock = Mock::default();

        send_request(&mut mock, &req).unwrap();

        assert_eq!(mock.written, frame(&serde_cbor::ser::to_vec(&req).unwrap()));
    }

    // receive_response: replies

    #[test]
    fn receive_returns_reply() {
        let reply = Response::Init { args: ["enclave", "--flag"].map(ToString::to_string).to_vec() };
        assert_eq!(receive(runner_reply(&reply)), Ok(reply));
    }

    #[test]
    fn receive_reads_exactly_one_frame() {
        let mut input = runner_reply(&Response::Closed);
        input.extend(runner_reply(&Response::Bound { local: localhost(80) }));
        let mut mock = Mock::replying(input);

        assert_eq!(receive_response(&mut mock), Ok(Response::Closed));
        assert_eq!(receive_response(&mut mock), Ok(Response::Bound { local: localhost(80) }));
    }

    // receive_response: runner errors

    #[test]
    fn command_error_becomes_io_error() {
        let reply = Response::Failed(RunnerError::Command(ErrorKind::ConnectionRefused));
        assert_eq!(receive(runner_reply(&reply)), Err(Error::IoError(ErrorKind::ConnectionRefused)));
    }

    #[test]
    fn system_error_becomes_system_error() {
        let reply = Response::Failed(RunnerError::SystemError(104));
        assert_eq!(receive(runner_reply(&reply)), Err(Error::SystemError(104)));
    }

    #[test]
    fn other_runner_errors_are_not_lost() {
        for err in [RunnerError::ConnectionNotFound, RunnerError::Unknown, RunnerError::VsockError] {
            let result = receive(runner_reply(&Response::Failed(err)));
            assert!(matches!(result, Err(Error::Other(_))), "got {:?}", result);
        }
    }

    // receive_response: broken frames

    #[test]
    fn empty_or_short_length_is_unexpected_eof() {
        assert_eq!(receive(Vec::new()), Err(Error::IoError(ErrorKind::UnexpectedEof)));
        assert_eq!(receive([1, 0, 0].to_vec()), Err(Error::IoError(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn truncated_body_is_unexpected_eof() {
        let mut input = runner_reply(&Response::Closed);
        input.pop();
        assert_eq!(receive(input), Err(Error::IoError(ErrorKind::UnexpectedEof)));
    }

    #[test]
    fn garbage_body_is_deserialization_error() {
        assert_eq!(receive(frame(&[0xff, 0xff, 0xff])), Err(Error::DeserializationError));
    }

    // Error conversions and helpers

    #[test]
    fn vsock_errors_map_to_client_errors() {
        let cases = [
            (vsock::Error::EntropyError, Error::Other("EntropyError".to_string())),
            (vsock::Error::ReservedPort, Error::InvalidInput),
            (vsock::Error::SystemError(13), Error::SystemError(13)),
            (vsock::Error::WrongAddressType, Error::InvalidInput),
            (vsock::Error::ZeroDurationTimeout, Error::InvalidInput),
            (vsock::Error::WriteZero, Error::IoError(ErrorKind::WriteZero)),
            (vsock::Error::UnexpectedEof, Error::IoError(ErrorKind::UnexpectedEof)),
        ];
        for (from, expected) in cases {
            assert_eq!(Error::from(from), expected);
        }
    }

    #[test]
    fn error_display() {
        assert_eq!(Error::InvalidInput.to_string(), "invalid input");
        assert_eq!(Error::SystemError(104).to_string(), "system error 104");
        assert_eq!(Error::IoError(ErrorKind::NotFound).to_string(), "I/O error: NotFound");
        assert_eq!(Error::MissingFd.to_string(), "missing file descriptor");
        assert_eq!(Error::Other("boom".to_string()).to_string(), "boom");
    }

    #[test]
    fn connection_info_accessors() {
        let stream = ConnectionInfo::new_stream_info(5, localhost(1), localhost(2), Some(7));
        assert_eq!(stream.enclave_port(), 5);
        assert_eq!(stream.fd(), Ok(7));

        let listener = ConnectionInfo::new_listener_info(localhost(3), 6, None);
        assert_eq!(listener.enclave_port(), 6);
        assert_eq!(listener.fd(), Err(Error::MissingFd));
    }

    fn localhost(port: u16) -> Addr {
        Addr::IPv4 { ip: [127, 0, 0, 1], port }
    }
}
