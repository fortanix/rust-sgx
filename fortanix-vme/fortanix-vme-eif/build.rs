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

    // Compile hello_world binary
    // The binary during the fortanixvme development is created by the following command:
    // `gcc -o a.out main.c -static -static-libgcc -flto`
    println!("cargo:rerun-if-changed=tests/hello_world.c");
    let compiler = cc::Build::new().get_compiler();
    let mut cmd = compiler.to_command();
    cmd.arg("tests/hello_world.c")
        .args(["-static", "-static-libgcc", "-flto"])
        .args(["-o", "tests/data/hello_world"]);
    let status = cmd.status().expect("Failed to execute C compiler");
    if !status.success() {
        panic!("Compilation failed, command: {:?}", cmd);
    }
}
