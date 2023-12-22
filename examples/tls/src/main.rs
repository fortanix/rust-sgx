/* Copyright (c) Fortanix, Inc. */

extern crate chrono;
extern crate mbedtls;

use chrono::prelude::*;

use mbedtls::alloc::Box as MbedtlsBox;
use mbedtls::alloc::List as MbedtlsList;
use mbedtls::hash::Type::Sha256;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::certificate::{Builder, Certificate};
use mbedtls::x509::Time;
use mbedtls::Result as TlsResult;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const RSA_KEY_SIZE: u32 = 3072;
const RSA_KEY_EXP: u32 = 0x10001;
const DAYS_TO_SES: u64 = 86400;
const CERT_VAL_SECS: u64 = 365 * DAYS_TO_SES;

trait ToTime {
    fn to_time(&self) -> Time;
}

impl ToTime for chrono::DateTime<Utc> {
    fn to_time(&self) -> Time {
        Time::new(
            self.year() as _,
            self.month() as _,
            self.day() as _,
            self.hour() as _,
            self.minute() as _,
            self.second() as _,
        )
        .unwrap()
    }
}

fn get_validity() -> (Time, Time) {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = start + CERT_VAL_SECS;
    let not_before = Utc.timestamp_opt(start as _, 0).unwrap();
    let not_after = Utc.timestamp_opt(end as _, 0).unwrap();
    (not_before.to_time(), not_after.to_time())
}

/// The below generates a key and a self signed certificate
/// to configure the TLS context.
/// SGX applications should not rely on untrusted sources for their key.
/// Ideally, enclaves communicating via TLS should, ideally,
/// also verify attestation information.
/// along with traditional certificate verification.
/// But this example doesn't show that.
fn get_key_and_cert() -> (Pk, MbedtlsBox<Certificate>) {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, RSA_KEY_SIZE, RSA_KEY_EXP).unwrap();
    let mut key_i = Pk::generate_rsa(&mut rng, RSA_KEY_SIZE, RSA_KEY_EXP).unwrap();
    let (not_before, not_after) = get_validity();

    let cert = Certificate::from_der(
        &Builder::new()
            .subject_key(&mut key)
            .subject_with_nul("CN=mbedtls-server.example\0")
            .unwrap()
            .issuer_key(&mut key_i)
            .issuer_with_nul("CN=mbedtls-server.example\0")
            .unwrap()
            .validity(not_before, not_after)
            .unwrap()
            .serial(&[5])
            .unwrap()
            .signature_hash(Sha256)
            .write_der_vec(&mut rng)
            .unwrap(),
    )
    .unwrap();
    (key, cert)
}

/// Establish a TLS connection with a randomly generated key and
/// a self signed certificate.
/// After a session is established, echo the incoming stream to the client.
/// till EOF is detected.
fn serve(conn: TcpStream, config: Arc<Config>) -> TlsResult<()> {
    let mut ctx = Context::new(config);

    let mut buf = String::new();
    ctx.establish(conn, None)?;
    println!("Connection established!");
    let mut reader = BufReader::new(ctx);
    while let Ok(1..=std::usize::MAX) = reader.read_line(&mut buf) {
        let session = reader.get_mut();
        session.write_all(&buf.as_bytes()).unwrap();
        buf.clear();
    }
    Ok(())
}

fn create_server_config(
    cert: MbedtlsBox<Certificate>,
    key: Pk,
) -> Result<Arc<Config>, mbedtls::Error> {
    let rng = Rdrand;
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(Arc::new(rng));
    let mut certs = MbedtlsList::new();
    certs.push(cert);
    config.push_cert(Arc::new(certs), Arc::new(key))?;
    let config = Arc::new(config);
    Ok(config)
}

/// The below main() starts a TLS echo server on `local host:7878`.
fn main() {
    let (key, cert) = get_key_and_cert();
    let config = create_server_config(cert, key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let _ = serve(stream, config.clone()).unwrap();
        println!("Connection closed!");
    }
}
