/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::future::Future;
use std::io::Result as IoResult;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{ChildStdin, ChildStdout, Command};

use aesm_client::AesmClient;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use sgxs_loaders::isgx::Device as IsgxDevice;

/// This example demonstrates use of usercall extensions.
/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "cat" which actually connects the enclave application to
/// stdin and stdout of `cat` process.
struct CatService {
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl CatService {
    // SAFETY: `Self` doesn't implement `Drop` or `Unpin`, and isn't `repr(packed)`
    pin_utils::unsafe_pinned!(stdin: ChildStdin);
    pin_utils::unsafe_pinned!(stdout: ChildStdout);

    fn new() -> Result<CatService, std::io::Error> {
        Command::new("/bin/cat")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .map(|mut c| CatService {
                stdin: c.stdin.take().unwrap(),
                stdout: c.stdout.take().unwrap(),
            })
    }
}

impl AsyncRead for CatService {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<IoResult<()>> {
        self.stdout().poll_read(cx, buf)
    }
}

impl AsyncWrite for CatService {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8]
    ) -> Poll<IoResult<usize>> {
        self.stdin().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        self.stdin().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<IoResult<()>> {
        self.stdin().poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct ExternalService;
// Ignoring local_addr and peer_addr, as they are not relavent in the current context.
impl UsercallExtension for ExternalService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> +'future>> {
        async move {
            // If the passed address is not "cat", we return none, whereby the passed address gets treated as
            // an IP address which is the default behavior.
            match &*addr {
                "cat" => {
                    let stream = CatService::new()?;
                    Ok(Some(Box::new(stream) as _))
                }
                _ => Ok(None),
            }
        }.boxed_local()
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
