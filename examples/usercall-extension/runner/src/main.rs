/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
extern crate tokio;

use aesm_client::AesmClient;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;
use tokio::io::{AsyncRead, AsyncWrite};
use std::io::{Read, Result as IoResult, Write};
use std::process::{Child, Command, Stdio};
use tokio::sync::lock::Lock;
use tokio::prelude::Async;

/// This example demonstrates use of usercall extensions.
/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "cat" which actually connects the enclave application to
/// stdin and stdout of `cat` process.
struct CatService {
    c: Lock<Child>,
}

impl CatService {
    fn new() -> Result<CatService, std::io::Error> {
        Command::new("/bin/cat")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .map(|c| Lock::new(c))
            .map(|c| CatService { c })
    }
}

macro_rules! poll_lock_wouldblock {
    ($lock:expr) => {
        match $lock.clone().poll_lock() {
            Async::NotReady => Err(std::io::ErrorKind::WouldBlock.into()),
            Async::Ready(ret) => IoResult::Ok(ret),
        }
    }
}

impl Read for CatService {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        poll_lock_wouldblock!(self.c)?.stdout.as_mut().unwrap().read(buf)
    }
}

impl Write for CatService {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        poll_lock_wouldblock!(self.c)?.stdin.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        poll_lock_wouldblock!(self.c)?.stdin.as_mut().unwrap().flush()
    }
}

impl AsyncRead for CatService {
}

impl AsyncWrite for CatService {
    fn shutdown(&mut self) -> tokio::prelude::Poll<(), std::io::Error> {
        Ok(().into())
    }
}

#[derive(Debug)]
struct ExternalService;
// Ignoring local_addr and peer_addr, as they are not relavent in the current context.
impl UsercallExtension for ExternalService {
    fn connect_stream(
        &self,
        addr: &str,
        _local_addr: Option<&mut String>,
        _peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn AsyncStream>>> {
        // If the passed address is not "cat", we return none, whereby the passed address gets treated as
        // an IP address which is the default behavior.
        match &*addr {
            "cat" => {
                let stream = CatService::new()?;
                Ok(Some(Box::new(stream)))
            }
            _ => Ok(None),
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

fn main() {
    let file = parse_args().unwrap();

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder.dummy_signature();
    enclave_builder.usercall_extension(ExternalService);
    let enclave = enclave_builder.build(&mut device).unwrap();

    enclave
        .run()
        .map_err(|e| {
            println!("Error while executing SGX enclave.\n{}", e);
            std::process::exit(1)
        })
        .unwrap();
}
