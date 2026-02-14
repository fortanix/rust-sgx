/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, ErrorKind as IoErrorKind, Read, Result as IoResult};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;

use futures::FutureExt;
use futures::lock::Mutex;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc as async_mpsc};

use super::{AsyncListener, AsyncStream, StreamRouter};

/// The standard stream router using the host OS.
///
/// The basic stream elements 0, 1, and 2 connect to stdin, stdout, and stderr, respectively.
///
/// Connect requests are translated into outbound TCP connections.
///
/// Bind requests are translated into incoming TCP listeners.
pub struct OsStreamRouter {
    _private: ()
}

impl OsStreamRouter {
    pub fn new() -> Box<dyn StreamRouter + Send + Sync> {
        Box::new(OsStreamRouter {
            _private: ()
        })
    }
}

fn set_opt_from_sockaddr(dst: Option<&mut String>, f: impl FnOnce() -> IoResult<std::net::SocketAddr>) {
    if let Some(dst) = dst {
        *dst = match f() {
            Ok(addr) => addr.to_string(),
            Err(_) => "error".into(),
        }
    }
}

impl StreamRouter for OsStreamRouter {
    fn basic_streams(&self) -> Vec<Box<dyn AsyncStream>> {
        vec![
            Box::new(ReadOnly { inner: Stdin }),
            Box::new(WriteOnly { inner: tokio::io::stdout() }),
            Box::new(WriteOnly { inner: tokio::io::stderr() }),
        ]
    }

    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
        peer_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Box<dyn AsyncStream>>> + Send +'future>> {
        (async move {
            let stream = tokio::net::TcpStream::connect(addr).await?;

            set_opt_from_sockaddr(local_addr, || stream.local_addr());
            set_opt_from_sockaddr(peer_addr, || stream.peer_addr());
            
            Ok(Box::new(stream) as _)
        }).boxed()
    }

    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Box<dyn AsyncListener>>> + Send + 'future>> {
        (async move {
            let socket = tokio::net::TcpListener::bind(addr).await?;

            set_opt_from_sockaddr(local_addr, || socket.local_addr());

            Ok(Box::new(socket) as _)
        }).boxed()
    }
}

impl AsyncListener for tokio::net::TcpListener {
    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> Poll<tokio::io::Result<Box<dyn AsyncStream>>> {
        tokio::net::TcpListener::poll_accept(&self, cx).map_ok(|(stream, stream_peer_addr)| {
                set_opt_from_sockaddr(local_addr, || stream.local_addr());
                set_opt_from_sockaddr(peer_addr, move || Ok(stream_peer_addr));

                Box::new(stream) as _
        })
    }
}

pin_project! {
    struct ReadOnly<R> {
        #[pin]
        inner: R
    }
}
pin_project! {
    struct WriteOnly<W> {
        #[pin]
        inner: W
    }
}

macro_rules! forward {
    (fn $n:ident(mut self: Pin<&mut Self> $(, $p:ident : $t:ty)*) -> $ret:ty) => {
        fn $n(self: Pin<&mut Self> $(, $p: $t)*) -> $ret {
            self.project().inner.$n($($p),*)
        }
    }
}

impl<R: std::marker::Unpin + AsyncRead> AsyncRead for ReadOnly<R> {
    forward!(fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<tokio::io::Result<()>>);
}

impl<T> AsyncRead for WriteOnly<T> {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context, _buf: &mut ReadBuf) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }
}

impl<T> AsyncWrite for ReadOnly<T> {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, _buf: &[u8]) -> Poll<tokio::io::Result<usize>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Err(IoErrorKind::BrokenPipe.into()))
    }
}

impl<W: std::marker::Unpin + AsyncWrite> AsyncWrite for WriteOnly<W> {
    forward!(fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<tokio::io::Result<usize>>);
    forward!(fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>>);
    forward!(fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<tokio::io::Result<()>>);
}

struct Stdin;

impl AsyncRead for Stdin {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<tokio::io::Result<()>> {
        const BUF_SIZE: usize = 8192;

        struct AsyncStdin {
            rx: async_mpsc::Receiver<VecDeque<u8>>,
            buf: VecDeque<u8>,
        }

        lazy_static::lazy_static! {
            static ref STDIN: Mutex<AsyncStdin> = {
                let (tx, rx) = async_mpsc::channel(8);
                thread::spawn(move || {
                    let mut buf = [0u8; BUF_SIZE];
                    while let Ok(len) = io::stdin().read(&mut buf) {
                        if len == 0 {
                            continue
                        }

                        if tx.try_send(buf[..len].to_vec().into()).is_err() {
                            return
                        };
                    }
                });
                Mutex::new(AsyncStdin { rx, buf: VecDeque::new() })
            };
        }

        match Pin::new(&mut STDIN.lock()).poll(cx) {
            Poll::Ready(mut stdin) => {
                if stdin.buf.is_empty() {
                    let pipeerr = tokio::io::Error::new(tokio::io::ErrorKind::BrokenPipe, "broken pipe");
                    stdin.buf = match Pin::new(&mut stdin.rx).poll_recv(cx) {
                        Poll::Ready(Some(vec)) => vec,
                        Poll::Ready(None) => return Poll::Ready(Err(pipeerr)),
                        _ => return Poll::Pending,
                    };
                }
                let inbuf = match stdin.buf.as_slices() {
                    (&[], inbuf) => inbuf,
                    (inbuf, _) => inbuf,
                };
                let len = cmp::min(buf.remaining(), inbuf.len());
                buf.put_slice(&inbuf[..len]);
                stdin.buf.drain(..len);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending
        }
    }
}
