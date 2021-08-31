/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate byteorder;
extern crate enclave_runner;
extern crate libc;
extern crate sgxs_loaders;

use aesm_client::AesmClient;
use enclave_runner::usercalls::{SyncListener, SyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;
use std::io;

use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

/// This example demonstrates use of usercall extensions for bind call.
/// User call extension allow the enclave code to "bind" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to bind to an address and advance the stream before returning it to enclave
/// This can be useful to strip protocol encapsulations, say while servicing requests load balanced by HA Proxy.
/// This example demonstrates de-encapsulation for various HA proxy configurations before handing over the stream to the enclave.
/// To simulate HA proxy configurations, the runner spawns a thread that connects to the same address which enclave binds to and
/// writes encapsulated test data for various HA proxy configurations to the stream.

const SIZE_HEADER_SIG: usize = 12;
static HEADER_SIG: [u8; SIZE_HEADER_SIG] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const V2CMD_LOCAL: u8 = 0x2_0;
const V2CMD_PROXY: u8 = 0x2_1;
const FAMILY_UNSPEC: u8 = 0;
const FAMILY_TCP4: u8 = 0x11;
const FAMILY_TCP6: u8 = 0x21;

struct ProxyIpv4Addr {
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
}

impl ProxyIpv4Addr {
    fn from_reader(rdr: &mut impl Read) -> IoResult<Self> {
        let src_addr = rdr.read_u32::<NetworkEndian>()?;
        let dst_addr = rdr.read_u32::<NetworkEndian>()?;
        let src_port = rdr.read_u16::<NetworkEndian>()?;
        let dst_port = rdr.read_u16::<NetworkEndian>()?;

        Ok(ProxyIpv4Addr {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        })
    }
}
impl From<ProxyIpv4Addr> for (SocketAddr, SocketAddr) {
    fn from(proxy_addr: ProxyIpv4Addr) -> (SocketAddr, SocketAddr) {
        let src_ip_addr: Ipv4Addr = proxy_addr.src_addr.into();
        let dst_ip_addr: Ipv4Addr = proxy_addr.dst_addr.into();
        let local_addr = SocketAddr::new(src_ip_addr.into(), proxy_addr.src_port);
        let peer_addr = SocketAddr::new(dst_ip_addr.into(), proxy_addr.dst_port);
        (local_addr, peer_addr)
    }
}

#[derive(Default)]
struct ProxyIpv6Addr {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
}

impl ProxyIpv6Addr {
    fn from_reader(rdr: &mut impl Read) -> IoResult<Self> {
        let mut addr = ProxyIpv6Addr::default();

        let _ = rdr.read_exact(&mut addr.src_addr[..])?;
        let _ = rdr.read_exact(&mut addr.dst_addr[..])?;
        addr.src_port = rdr.read_u16::<NetworkEndian>()?;
        addr.dst_port = rdr.read_u16::<NetworkEndian>()?;

        Ok(addr)
    }
}

impl From<ProxyIpv6Addr> for (SocketAddr, SocketAddr) {
    fn from(proxy_addr: ProxyIpv6Addr) -> (SocketAddr, SocketAddr) {
        let src_ip_addr: Ipv6Addr = proxy_addr.src_addr.into();
        let dst_ip_addr: Ipv6Addr = proxy_addr.dst_addr.into();
        let local_addr = SocketAddr::new(src_ip_addr.into(), proxy_addr.src_port);
        let peer_addr = SocketAddr::new(dst_ip_addr.into(), proxy_addr.dst_port);
        (local_addr, peer_addr)
    }
}

enum ProxyAddrType {
    V4,
    V6,
    Unspec,
}

struct ProxyAddrReader {
    ty: ProxyAddrType,
    len: u16,
}

impl ProxyAddrReader {
    fn new(ty: ProxyAddrType, len: u16) -> ProxyAddrReader {
        ProxyAddrReader { ty, len }
    }
    fn read(&self, rdr: &mut impl Read) -> IoResult<Option<(SocketAddr, SocketAddr)>> {
        match self.ty {
            ProxyAddrType::V4 => {
                if self.len as usize != size_of::<ProxyIpv4Addr>() {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Unexpected address length received",
                    ))?;
                }
                let addr = ProxyIpv4Addr::from_reader(rdr)?;
                let (local, peer) = addr.into();
                Ok(Some((local, peer)))
            }
            ProxyAddrType::V6 => {
                if self.len as usize != size_of::<ProxyIpv6Addr>() {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Unexpected address length received",
                    ))?;
                }
                let addr = ProxyIpv6Addr::from_reader(rdr)?;
                let (local, peer) = addr.into();
                Ok(Some((local, peer)))
            }
            ProxyAddrType::Unspec => {
                io::copy(&mut rdr.take(self.len as _), &mut io::sink())?;
                Ok(None)
            }
        }
    }
}

#[allow(unused)]
struct ProxyHdrV2 {
    sig: [u8; SIZE_HEADER_SIG],   /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    ver_cmd: u8,                  /* protocol version and command*/
    fam: u8,                      /* protocol family and address*/
    len: u16,                     /* number of following bytes part of the header*/
    addr_reader: ProxyAddrReader, /* read len bytes into a tuple of SocketAddr */
}

impl ProxyHdrV2 {
    fn from_reader(rdr: &mut impl Read) -> IoResult<Self> {
        let mut sig: [u8; SIZE_HEADER_SIG] = [0; SIZE_HEADER_SIG];
        let _ = rdr.read_exact(&mut sig[..])?;
        if &sig[..] != HEADER_SIG {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Protocol header signature mismatch",
            ));
        }
        let ver_cmd = rdr.read_u8()?;
        let fam = rdr.read_u8()?;
        let len = rdr.read_u16::<NetworkEndian>()?;
        let addr_reader = match (ver_cmd, fam) {
            (V2CMD_LOCAL, FAMILY_UNSPEC) => ProxyAddrReader::new(ProxyAddrType::Unspec, len),
            (V2CMD_PROXY, FAMILY_TCP4) => ProxyAddrReader::new(ProxyAddrType::V4, len),
            (V2CMD_PROXY, FAMILY_TCP6) => ProxyAddrReader::new(ProxyAddrType::V6, len),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Unsupported version/command/family",
            ))?,
        };

        Ok(ProxyHdrV2 {
            sig,
            ver_cmd,
            fam,
            len,
            addr_reader,
        })
    }
}
fn read_proxy_protocol_header(
    stream: &mut TcpStream,
) -> IoResult<Option<(SocketAddr, SocketAddr)>> {
    let hdr = ProxyHdrV2::from_reader(stream)?;
    hdr.addr_reader.read(stream)
}

struct ProxyProtocol {
    listener: TcpListener,
}

impl ProxyProtocol {
    fn new(addr: &str) -> IoResult<(Self, String)> {
        TcpListener::bind(addr).map(|listener| {
            let local_address = match listener.local_addr() {
                Ok(local_address) => local_address.to_string(),
                Err(_) => "error".to_string(),
            };
            (ProxyProtocol { listener }, local_address)
        })
    }
}

impl SyncListener for ProxyProtocol {
    fn accept(&self, local_addr: Option<&mut String>, peer_addr: Option<&mut String>) -> IoResult<Box<dyn SyncStream>> {
        let (mut stream, peer_address_tcp) = self.listener.accept()?;
        let local_address_tcp = stream.local_addr()?;
        eprintln!(
            "runner:: bind - local_address is {}, peer address is {}",
            local_address_tcp, peer_address_tcp
        );
        let (local_address, peer_address) = read_proxy_protocol_header(&mut stream)?
            .unwrap_or((local_address_tcp, peer_address_tcp));

        if let Some(local_addr) = local_addr {
            *local_addr = local_address.to_string();
        }

        if let Some(peer_addr) = peer_addr {
            *peer_addr = peer_address.to_string();
        }

        Ok(Box::new(stream))
    }
}

const HAPROXY_ADDRESS: &str = "localhost:6010";

#[derive(Debug)]
struct HaproxyService;
impl UsercallExtension for HaproxyService {
    fn bind_stream(
        &self,
        addr: &str,
        local_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncListener>>> {
        if addr == HAPROXY_ADDRESS {
            let (listener, local_address) = ProxyProtocol::new(addr)?;
            if let Some(local_addr) = local_addr {
                (*local_addr) = local_address;
            }

            Ok(Some(Box::new(listener)))
        } else {
            Ok(None)
        }
    }
}

fn usage(name: String) {
    println!("Usage:\n{} <path_to_sgxs_file>", name);
}

fn parse_args() -> Result<String, ()> {
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        2 => Ok(args[1].to_owned()),
        _ => {
            usage(args[0].to_owned());
            Err(())
        }
    }
}

fn run_server(file: String) -> Result<(), ()> {
    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder.dummy_signature();
    enclave_builder.usercall_extension(HaproxyService);
    let enclave = enclave_builder.build(&mut device).unwrap();

    enclave.run().map_err(|e| {
        eprintln!("Error in running enclave {}", e);
    })
}

struct SimulateHaProxyConfig;
impl SimulateHaProxyConfig {
    fn test_proxy_header(header: &[u8], profile_name: &str) {
        static TEST_DATA: &'static str = "connection test data";

        thread::sleep(std::time::Duration::from_secs(2));
        let mut stream = TcpStream::connect(HAPROXY_ADDRESS).unwrap();
        stream.write_all(header).unwrap();
        stream
            .write_all(&format!("{} {}\n", TEST_DATA, profile_name).as_bytes())
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    }

    fn ipv4() {
        // HAProxy configuration:
        //
        // listen test
        //   bind :8003
        //   server s 127.0.0.1:8002 send-proxy-v2
        static TEST_PROXY_TCPV4: &'static [u8] = &[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
            0x00, 0x0c, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x97, 0x32, 0x1f, 0x43,
        ];

        Self::test_proxy_header(TEST_PROXY_TCPV4, "ipv4");
    }

    fn ipv6() {
        // HAProxy configuration:
        //
        // listen test
        //   bind ipv6@:8003
        //   server s 127.0.0.1:8002 send-proxy-v2
        static TEST_PROXY_TCPV6: &'static [u8] = &[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x21,
            0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x83, 0xb8, 0x1f, 0x43,
        ];

        Self::test_proxy_header(TEST_PROXY_TCPV6, "ipv6");
    }

    fn local() {
        // HAProxy configuration:
        //
        // listen test
        //   bind :8003
        //   server s /tmp/unix.sock check inter 10000 send-proxy-v2
        //
        // NB: HAProxy NEVER sends a local command for health checks over TCP;
        // it will always put the local connections addresses in a regular
        // proxy command. This configuration only works because HAProxy version
        // <=1.8 never puts UNIX socket addresses in a proxy command. It's
        // entirely possible that it will start doing that at some point, at
        // which point this configuration might no longer generate the correct
        // test data.
        static TEST_LOCAL: &'static [u8] = &[
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x20, 0x00,
            0x00, 0x00,
        ];

        Self::test_proxy_header(TEST_LOCAL, "local");
    }
}

fn run_client() -> Result<(), Error> {
    SimulateHaProxyConfig::ipv4();
    SimulateHaProxyConfig::ipv6();
    SimulateHaProxyConfig::local();
    Ok(())
}

fn main() {
    let file = parse_args().unwrap();
    let server = thread::spawn(move || run_server(file));
    let client = thread::spawn(move || run_client());

    let _ = client.join().unwrap();
    let _ = server.join().unwrap();
}
