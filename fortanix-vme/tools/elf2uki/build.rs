use std::process::Command;

// Build `init` executable, to be used in constructing the initramfs
fn main() {
    println!("cargo::rerun-if-changed=blobs/build_init");

    let output = Command::new("./blobs/build_init/update_init.sh")
        .output()
        .unwrap();

    if !output.status.success() {
        panic!(
            "failed to compile init script: {} \n\n sterr : {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

