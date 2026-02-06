use std::fs::File;
use std::io::Write;
use std::path::Path;
use rustc_version::{Version, version, version_meta};

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux" {
        const LIBNAME: &str = "fortanix_enclave_runner_fake_vdso";
        // using var instead of var_os because we need to print it later
        let out_dir = std::env::var("OUT_DIR").unwrap();

        // FIXME: need to link to fake VDSO due to https://github.com/rust-lang/rust/issues/58713
        File::create(&Path::new(&out_dir).join(format!("lib{}.so", LIBNAME)))
            .unwrap()
            .write_all(include_bytes!("fake-vdso/fake-vdso.so"))
            .unwrap();

        println!("cargo:rustc-link-lib=dylib={}", LIBNAME);
        println!("cargo:rustc-link-search=native={}", out_dir);
    }

    if version().unwrap() <= Version::parse("1.84.0").unwrap() {
        println!("cargo::rustc-cfg=feature=\"err-compat\"");
    }
}
