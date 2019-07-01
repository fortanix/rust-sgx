// Copyright 2017 Fortanix, Inc.
#![deny(warnings)]

extern crate hyper_native_tls;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
extern crate openssl;
extern crate native_tls;
extern crate ftx_pkix;
#[macro_use]
extern crate quick_error;
extern crate rustc_serialize;

use std::io::{Error as IoError, Read};
use std::env;
use std::fs::File;
use std::path::Path;

use hyper_native_tls::NativeTlsClient;
use native_tls::{Error as NativeTlsError, TlsConnector};

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use native_tls::backend::openssl::TlsConnectorBuilderExt;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use openssl::ssl::SSL_VERIFY_NONE;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use openssl::x509::X509_FILETYPE_PEM;
use pkix::pem::{PemBlock, pem_to_der, PEM_CERTIFICATE};

#[cfg(any(target_os = "windows", target_os = "macos"))]
quick_error!{
    #[derive(Debug)]
    pub enum OpensslError {
        OpensslError {
            description("openssl error on non-openssl platform, should not happen")
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
type OpensslError = openssl::error::ErrorStack;

quick_error!{
    #[derive(Debug)]
    pub enum Error {
        IoError(e: IoError) {
            from()
            cause(e)
            description(e.description())
            display("io error: {}", e)
        }
        // This could be represented by a NativeTlsError, but not sure how to access the constructor.
        // TODO: remove once all openssl specifics are replaced with cross-platform native_tls functionality.
        OpensslError(e: OpensslError) {
            from()
            cause(e)
            description(e.description())
            display("openssl error: {}", e)
        }
        NativeTlsError(e: NativeTlsError) {
            from()
            cause(e)
            description(e.description())
            display("native_tls error: {}", e)
        }
        InvalidCertificateInCaFile {
            description("Invalid certificiate in CA file")
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;


fn generic_client_connector() -> Result<TlsConnector> {
    let mut builder = TlsConnectorBuilder(native_tls::TlsConnector::builder()?);
    builder
        .with_probed_system_ca_list()?
        .with_ca_cert_from_env()?;
    Ok(builder.build()?)
}

/// Convenience function to return a safe, general-purpose client.
pub fn generic_client() -> Result<NativeTlsClient> {
    generic_client_connector().map(Into::into)
}

/// Returns an INSECURE client that does not perform certificate validation.
/// Use with extreme caution.
// TODO: replace with cross-platform native_tls functionality when available
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[allow(deprecated)]
pub fn insecure_client() -> Result<NativeTlsClient> {
    let mut builder = TlsConnectorBuilder(native_tls::TlsConnector::builder()?);
    {
        let ctx_builder = builder.0.builder_mut().builder_mut();
        ctx_builder.set_verify(SSL_VERIFY_NONE);
    } // release borrow of builder
    let mut client: NativeTlsClient = builder.build()?.into();
    client.danger_disable_hostname_verification(true);
    Ok(client)
}

pub struct TlsConnectorBuilder(native_tls::TlsConnectorBuilder);

impl TlsConnectorBuilder {
    /// Returns a new builder wrapping a native_tls::TlsConnectorBuilder with no additional
    /// configuration.
    pub fn new() -> Result<Self> {
        Ok(TlsConnectorBuilder(native_tls::TlsConnector::builder()?))
    }

    pub fn build(self) -> Result<native_tls::TlsConnector> {
        Ok(self.0.build()?)
    }

    /// Returns a new builder with the default configuration.
    pub fn new_with_defaults() -> Result<Self> {
        let mut builder = Self::new()?;
        builder
            .with_probed_system_ca_list()?
            .with_ca_cert_from_env()?;
        Ok(builder)
    }

    pub fn with_probed_system_ca_list(&mut self) -> Result<&mut Self> {
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        fn fix_system_ca_list(_builder: &mut native_tls::TlsConnectorBuilder) {}

        /// On Linux, when statically linking OpenSSL, we need to look for and
        /// the configure location of the system-managed certificate store.
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        #[allow(deprecated)]
        fn fix_system_ca_list(builder: &mut native_tls::TlsConnectorBuilder) {
            extern crate openssl;
            extern crate openssl_probe;
            extern crate openssl_sys;
            use std::ptr;
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            let probe = openssl_probe::probe();

            let file = probe.cert_file.map(|p|CString::new(p.into_os_string().as_bytes()).expect("no NULL in path"));
            let path = probe.cert_dir.map(|p|CString::new(p.into_os_string().as_bytes()).expect("no NULL in path"));
            if file.is_some() || path.is_some() {
                unsafe {
                    if openssl_sys::SSL_CTX_load_verify_locations(builder.builder_mut().builder_mut().as_ptr(),
                                                  file.as_ref().map_or(ptr::null(), |s|s.as_ptr()) as *const _,
                                                  path.as_ref().map_or(ptr::null(), |s|s.as_ptr()) as *const _) <= 0 {
                        panic!("Unable to set OpenSSL certificate store path {:?}", openssl::error::ErrorStack::get())
                    }
                }
            }
        }

        fix_system_ca_list(&mut self.0);
        Ok(self)
    }

    /// Install a DER-format certificate from the file given by env var
    /// CA_FILE as a trusted root certificate.
    pub fn with_ca_cert_from_env(&mut self) -> Result<&mut Self> {
        if let Some(ca_file) = env::var_os("CA_FILE") {
            let mut f = File::open(ca_file)?;
            let mut cert = Vec::new();
            f.read_to_end(&mut cert)?;
            self.0.add_root_certificate(native_tls::Certificate::from_der(&cert)?)?;
        }
        Ok(self)
    }

    /// Install PEM-format certificate(s) from the given file as trusted
    /// root certificates.
    pub fn with_ca_certs_from_file<T>(&mut self, file: T) -> Result<&mut Self>
        where T: AsRef<Path>
    {
        let mut f = File::open(file)?;
        let mut certs = Vec::new();
        f.read_to_end(&mut certs)?;
        for cert_pem in PemBlock::new(&certs) {
            let cert_str = ::std::str::from_utf8(cert_pem)
                .map_err(|_| Error::InvalidCertificateInCaFile)?.trim();
            let cert_der = pem_to_der(cert_str, Some(PEM_CERTIFICATE))
                .ok_or_else(|| Error::InvalidCertificateInCaFile)?;
            let cert = native_tls::Certificate::from_der(&cert_der)?;
            self.0.add_root_certificate(cert)?;
        }
        Ok(self)
    }

    /// Use TLS client certificate and key from the given files.
    // TODO: replace with cross-platform native_tls functionality when available
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[allow(deprecated)]
    pub fn with_client_cert_and_key<C, K>(&mut self, cert: C, key: K) -> Result<&mut Self>
        where C: AsRef<Path>, K: AsRef<Path>
    {
        {
            let ctx_builder = self.0.builder_mut().builder_mut();
            ctx_builder.set_private_key_file(key, X509_FILETYPE_PEM)?;
            ctx_builder.set_certificate_chain_file(cert)?;
        } // release borrow of self
        Ok(&mut *self)
    }
}

#[test]
fn test_generic_client() {
    use std::net::TcpStream;

    let tls = generic_client_connector().unwrap();

    // Test successful connection
    let host = "badssl.com";
    let stream = TcpStream::connect((host, 443)).unwrap();
    tls.connect(host, stream).unwrap();

    // Test bad hostname
    let host = "wrong.host.badssl.com";
    let stream = TcpStream::connect((host, 443)).unwrap();
    tls.connect(host, stream).unwrap_err();

    // Test untrusted cert
    let host = "untrusted-root.badssl.com";
    let stream = TcpStream::connect((host, 443)).unwrap();
    tls.connect(host, stream).unwrap_err();
}
