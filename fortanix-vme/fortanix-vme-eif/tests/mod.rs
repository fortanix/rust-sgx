use std::io::Cursor;
use fortanix_vme_eif::{Builder, FtxEif};
use aws_nitro_blobs::{CMDLINE, INIT, KERNEL, KERNEL_CONFIG, NSM};

const HELLO_WORLD: &[u8] = include_bytes!(std::concat!(std::env!("OUT_DIR"), "/hello_world"));

#[test]
fn eif_creation_and_extraction() {
    let name = String::from("TestEnclave");
    let hello_world = Cursor::new(HELLO_WORLD);
    let init = Cursor::new(INIT);
    let nsm = Cursor::new(NSM);
    let kernel = Cursor::new(KERNEL);
    let kernel_config = Cursor::new(KERNEL_CONFIG);
    let eif = Builder::new(name, hello_world, init, nsm, kernel, kernel_config, CMDLINE)
        .build(Cursor::new(Vec::new()))
        .unwrap()
        .into_inner()
        .into_inner();

    let mut eif = FtxEif::new(Cursor::new(eif));
    assert_eq!(eif.application().unwrap(), HELLO_WORLD);
}
