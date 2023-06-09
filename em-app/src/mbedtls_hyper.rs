/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use hyper::net::{NetworkStream, SslClient, SslServer};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use mbedtls::ssl::{Config, Context};

// Native TLS compatibility - to move to native tls client in the future
#[derive(Clone)]
pub struct TlsStream<T> {
    context: Arc<Mutex<Context<T>>>,
}

impl<T: 'static> TlsStream<T> {
    pub fn new(context: Arc<Mutex<Context<T>>>) -> io::Result<Self> {
        if context.lock().unwrap().io_mut().is_none() {
            return Err(IoError::new(IoErrorKind::InvalidInput, "Peer set in context is not of expected type"));
        }

        Ok(TlsStream {
            context,
        })
    }
}

impl<T: 'static + io::Read + io::Write> io::Read for TlsStream<T>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.context.lock().unwrap().read(buf)
    }
}

impl<T: 'static + io::Read + io::Write> io::Write for TlsStream<T>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.context.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.context.lock().unwrap().flush()
    }
}

impl<T: 'static> NetworkStream for TlsStream<T>
    where T: NetworkStream
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().io_mut()
            .ok_or(IoError::new(IoErrorKind::NotFound, "No peer available"))?
            .set_write_timeout(dur)
    }
 }


#[derive(Clone)]
pub struct MbedSSLServer {
    rc_config: Arc<Config>,
}

impl MbedSSLServer {
    pub fn new(rc_config: Arc<Config>) -> Self {
        MbedSSLServer {
            rc_config,
        }
    }
}

/// An abstraction to allow any SSL implementation to be used with server-side HttpsStreams.
impl<T> SslServer<T> for MbedSSLServer
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    /// The protected stream.
    type Stream = TlsStream<T>;

    /// Wrap a server stream with SSL.
    fn wrap_server(&self, stream: T) -> Result<Self::Stream, hyper::Error> {
        let mut ctx = Context::new(self.rc_config.clone());
        ctx.establish(stream, None).map_err(|e| hyper::error::Error::Ssl(e.into()))?;

        Ok(TlsStream::new(Arc::new(Mutex::new(ctx))).expect("Software error creating TlsStream"))
    }
}

#[derive(Clone)]
pub struct MbedSSLClient {
    rc_config: Arc<Config>,
    verify_hostname: bool,

    // This can be used when verify_hostname is set to true.
    // It will force ssl client to send this specific SNI on all established connections disregarding any host provided by hyper.
    override_sni: Option<String>,
}

impl MbedSSLClient {
    #[allow(dead_code)]
    pub fn new(rc_config: Arc<Config>, verify_hostname: bool) -> Self {
        MbedSSLClient {
            rc_config,
            verify_hostname,
            override_sni: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_sni(rc_config: Arc<Config>, verify_hostname: bool, override_sni: Option<String>) -> Self {
        MbedSSLClient {
            rc_config,
            verify_hostname,
            override_sni,
        }
    }
}

impl<T> SslClient<T> for MbedSSLClient
    where T: NetworkStream + Send + Clone + fmt::Debug + Sync
{
    type Stream = TlsStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<TlsStream<T>> {
        let mut context = Context::new(self.rc_config.clone());

        let verify_hostname = match self.verify_hostname {
            true => Some(self.override_sni.as_ref().map(|v| v.as_str()).unwrap_or(host)),
            false => None,
        };

        match context.establish(stream, verify_hostname) {
            Ok(()) => Ok(TlsStream::new(Arc::new(Mutex::new(context))).expect("Software error creating TlsStream")),
            Err(e) => Err(hyper::Error::Ssl(Box::new(e))),
        }
    }
}

