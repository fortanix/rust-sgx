// Copyright 2017 Fortanix, Inc.
#![deny(warnings)]

extern crate hyper;
extern crate percent_encoding;
extern crate url;
extern crate rustc_serialize;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, Shutdown};
use std::time::Duration;

use hyper::method::Method;
use hyper::net::{HttpConnector, NetworkConnector, HttpStream, SslClient, NetworkStream};
use hyper::version::HttpVersion::Http11;
use percent_encoding::percent_decode;
use url::Url;
use rustc_serialize::base64::{ToBase64, STANDARD};


#[derive(Clone,Debug)]
pub enum ProxyConfig {
    None,
    Http(Url),
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig::None
    }
}

impl ProxyConfig {
    pub fn parse(config: &str) -> ::std::result::Result<ProxyConfig, ()> {
        let url: Url = config.parse().map_err(|_| ())?;
        if url.scheme() != "http" {
            return Err(());
        }
        url.host_str().ok_or(())?;
        Ok(ProxyConfig::Http(url))
    }
}

pub struct ProxiedHttpsConnector<S> {
    pub proxy_config: ProxyConfig,
    pub ssl: S,
}

impl<S: SslClient> ProxiedHttpsConnector<S> {
    fn http_proxy_connect(host: &str, port: u16, proxy_url: &Url) -> hyper::Result<HttpStream> {
        let mut stream = HttpConnector.connect(proxy_url.host_str().expect("validated"), proxy_url.port().unwrap_or(80), "http")?;
        let mut proxy_authorization = String::new();
        if !proxy_url.username().is_empty() || proxy_url.password().is_some() {
            let username = proxy_url.username();
            let mut basic_token: Vec<u8> = percent_decode(username.as_bytes()).collect();
            basic_token.push(b':');
            basic_token.extend(percent_decode(proxy_url.password().unwrap_or("").as_bytes()));
            proxy_authorization = format!("Proxy-Authorization: Basic {}\r\n", basic_token.to_base64(STANDARD));
        }
        write!(&mut stream, "{method} {host}:{port} {version}\r\nHost: {host}:{port}\r\n{proxy_authorization}\r\n",
               method = Method::Connect, host = host, port = port, version = Http11, proxy_authorization = proxy_authorization)?;
        stream.flush()?;
        let (mut buf, mut index) = (vec![0; 1024], 0);
        'outer: loop {
            if buf.len() == index {
                buf.resize(2 * index, 0);
            }
            index += stream.read(&mut buf[index..])?;
            let (mut headers, mut max_headers) = (Vec::new(), 10);
            loop {
                headers.resize(max_headers, httparse::EMPTY_HEADER);
                let mut result = httparse::Response::new(&mut headers);
                match result.parse(&buf[..index]) {
                    Ok(status) if status.is_complete() => return match result.code.expect("complete parsing lost code") {
                        200..=299 => Ok(stream),
                        _ => Err(hyper::Error::Status),
                    },
                    Ok(_) => continue 'outer,
                    Err(httparse::Error::TooManyHeaders) => { max_headers *= 2; continue },
                    Err(_) => return Err(hyper::Error::Status),
                }
            }
        }
    }
}


#[derive(Debug)]
pub enum Proxied<T1, T2> {
    Normal(T1),
    Tunneled(T2)
}


impl<T1: NetworkStream, T2: NetworkStream> io::Read for Proxied<T1, T2> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Proxied::Normal(ref mut t) => io::Read::read(t, buf),
            Proxied::Tunneled(ref mut t) => io::Read::read(t, buf),
        }
    }
}

impl<T1: NetworkStream, T2: NetworkStream> io::Write for Proxied<T1, T2> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Proxied::Normal(ref mut t) => io::Write::write(t, buf),
            Proxied::Tunneled(ref mut t) => io::Write::write(t, buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            Proxied::Normal(ref mut t) => io::Write::flush(t),
            Proxied::Tunneled(ref mut t) => io::Write::flush(t),
        }
    }
}

impl<T1: NetworkStream, T2: NetworkStream> NetworkStream for Proxied<T1, T2> {
    #[inline]
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        match *self {
            Proxied::Normal(ref mut s) => s.peer_addr(),
            Proxied::Tunneled(ref mut s) => s.peer_addr()
        }
    }

    #[inline]
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match *self {
            Proxied::Normal(ref inner) => inner.set_read_timeout(dur),
            Proxied::Tunneled(ref inner) => inner.set_read_timeout(dur)
        }
    }

    #[inline]
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match *self {
            Proxied::Normal(ref inner) => inner.set_write_timeout(dur),
            Proxied::Tunneled(ref inner) => inner.set_write_timeout(dur)
        }
    }

    #[inline]
    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        match *self {
            Proxied::Normal(ref mut s) => s.close(how),
            Proxied::Tunneled(ref mut s) => s.close(how)
        }
    }
}

impl<S: SslClient> NetworkConnector for ProxiedHttpsConnector<S> {
    type Stream = Proxied<HttpStream, <S as hyper::net::SslClient>::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> hyper::Result<Self::Stream> {
        let stream = match self.proxy_config {
            ProxyConfig::None => HttpConnector.connect(host, port, "http")?,
            ProxyConfig::Http(ref url) => Self::http_proxy_connect(host, port, url)?,
        };
        if scheme == "http" {
            Ok(Proxied::Normal(stream))
        } else if scheme == "https" {
            self.ssl.wrap_client(stream, host).map(|stream| Proxied::Tunneled(stream))
        } else {
            panic!("Scheme must be http or https, is {}", scheme)
        }
    }
}


