use rustc_version::{version, Version};

fn main() {
    // INTEL-SA-00334 -- Load Value Injection (LVI)
    if version().unwrap() >= Version::parse("1.49.0-nightly").unwrap() {
        println!("cargo:rustc-cfg=intel_sa_00334");
    }

    // INTEL-SA-00615 -- MMIO Stale Data
    if version().unwrap() >= Version::parse("1.64.0-nightly").unwrap() {
        println!("cargo:rustc-cfg=intel_sa_00615");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=IAS_EXTRA_ADVISORIES");
    println!("cargo:rerun-if-env-changed=IAS_QUOTE_STATUS");
}
