fn main() {
    println!("cargo:rerun-if-env-changed=SGX_SDK");
}
