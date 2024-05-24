fn main() {
    let mut dst = cmake::build(".");
    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());
}
