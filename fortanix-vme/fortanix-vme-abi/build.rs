use serde::Codegen;

use std::env;
use std::fs;
use std::path::Path;

#[derive(Codegen)]
#[derive(PartialEq, Eq, Debug)]
pub struct Test {
    pub field: u64,
}

#[derive(Codegen)]
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Connect {
        addr: String,
    },
    Bind {
        /// The address the listen to in the parent VM
        addr: String,
        /// The port the enclave is listening on to receive connections from the parent VM. This
        /// port will also be used to reference the connection
        enclave_port: u32,
    },
    Accept {
        /// The Vsock port the enclave is listening on
        enclave_port: u32,
    },
    Close {
        enclave_port: u32,
    },
    Info {
        enclave_port: u32,
        runner_port: Option<u32>,
    },
}

#[derive(Codegen)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    IPv4 {
        ip: [u8; 4],
        port: u16,
    },
    IPv6 {
        ip: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

#[derive(Codegen)]
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    Connected {
        /// The vsock port the proxy is listening on for an incoming connection
        proxy_port: u32,
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
    },
    Bound {
        /// The local TCP address the parent VM is listening on
        local: Addr,
    },
    IncomingConnection {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
        /// The vsock port number the runner will connect to the enclave in order to forward the
        /// incoming connection
        proxy_port: u32,
    },
    Closed,
    Info {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party for open connection, None for server sockets
        peer: Option<Addr>,
    },
    Failed(Error),
}

#[derive(Codegen)]
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    ConnectionNotFound,
    SystemError(i32),
    Unknown,
    VsockError,
}
    
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=src/abi.in.rs");
    let abi = fs::read_to_string("./src/abi.in.rs").unwrap();
    let abi = abi + &format!("{}\n{}\n{}\n", Request::type_definition(), Request::serialization_code(), Request::deserialization_code());
    let abi = abi + &format!("{}\n{}\n{}\n", Addr::type_definition(), Addr::serialization_code(), Addr::deserialization_code());
    let abi = abi + &format!("{}\n{}\n{}\n", Response::type_definition(), Response::serialization_code(), Response::deserialization_code());
    let abi = abi + &format!("{}\n{}\n{}\n", Error::type_definition(), Error::serialization_code(), Error::deserialization_code());
    let abi_out = Path::new(&out_dir).join("abi.out.rs");
    std::fs::write(abi_out, abi).expect("Failed to write generated code")

    /*
    let mtmp = Path::new(&out_dir).join("abi.rs");
    let code = format!("{}\n{}\n{}", Test::type_definition(), Test::serialization_code(), Test::deserialization_code());
    std::fs::write(mtmp, code).expect("Failed to write generated code")
    */
}
