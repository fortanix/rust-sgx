extern crate pkix;

use pkix::pem::{der_to_pem, PEM_CERTIFICATE_REQUEST};

#[path="../tests/fakes.rs"]
pub mod fakes;

fn main() {
    let csr = fakes::csr_der(fakes::random_printable_string);

    println!("{}", der_to_pem(&csr, PEM_CERTIFICATE_REQUEST));
}
