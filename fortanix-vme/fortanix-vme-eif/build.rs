#![deny(warnings)]
use blobs_tool::download::download_blobs;
use blobs_tool::utils::create_symlink;
use blobs_tool::BLOB_DEFAULT_DIR;
use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changes=CARGO_MANIFEST_DIR");

    let mut test_dir = PathBuf::from(format!(
        "{}/tests/data",
        env::var("CARGO_MANIFEST_DIR").expect("cargo manifest dir"),
    ));
    let output_dir = Path::new(BLOB_DEFAULT_DIR);
    for blob in download_blobs(output_dir).unwrap() {
        println!("cargo:rerun-if-changed={}", blob);
        create_symlink(&blob, &mut test_dir).unwrap();
    }
}
