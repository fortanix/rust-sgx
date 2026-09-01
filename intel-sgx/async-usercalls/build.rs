use std::env;
use std::process::Command;
use std::str;

// Enables configuration for non-stable features that are stabilized later.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(no_never_type)");

    let minor = match rustc_minor_version() {
        Some(minor) => minor,
        None => return,
    };
    if minor < 100 {
        println!("cargo:rustc-cfg=no_never_type");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
