extern crate pkix;

use pkix::pem::{der_to_pem, PEM_CERTIFICATE};

#[path="../tests/fakes.rs"]
pub mod fakes;

fn main() {
    let cert = fakes::cert_der(fakes::random_printable_string);

    println!("{}", der_to_pem(&cert, PEM_CERTIFICATE));
}
