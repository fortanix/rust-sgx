extern crate pkix;

use std::io::{Read, stdin};
use std::env::args;

use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
use pkix::x509::GenericCertificate;
use pkix::{FromBer, FromDer};

fn main() {
    let mut cert = String::new();
    stdin().read_to_string(&mut cert).unwrap();
    if args().skip(1).next() == Some("--ber".into()) {
        GenericCertificate::from_ber(&pem_to_der(&cert, Some(PEM_CERTIFICATE)).unwrap()).unwrap();
    } else {
        GenericCertificate::from_der(&pem_to_der(&cert, Some(PEM_CERTIFICATE)).unwrap()).unwrap();
    }
}
