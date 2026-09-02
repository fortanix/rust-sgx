use rustc_version::version;

// Enables configuration for non-stable features that are stabilized later.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(no_never_type)");
    let rustc_version = version().unwrap();

    if rustc_version.minor < 100 {
        println!("cargo:rustc-cfg=no_never_type");
    }
}
