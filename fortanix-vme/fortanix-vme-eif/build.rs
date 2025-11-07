#![deny(warnings)]

fn main() {
    // Compile hello_world binary
    // The binary during the fortanixvme development is created by the following command:
    // `gcc -o a.out main.c -static -static-libgcc -flto`
    println!("cargo:rerun-if-changed=tests/hello_world.c");
    let compiler = cc::Build::new().get_compiler();
    let mut cmd = compiler.to_command();
    let out_file = format!(
        "{}/hello_world",
        std::env::var("OUT_DIR").expect("OUT_DIR is missing")
    );

    cmd.arg("tests/hello_world.c")
        .args(["-static", "-static-libgcc", "-flto"])
        .args(["-o", &out_file]);
    let status = cmd.status().expect("Failed to execute C compiler");
    if !status.success() {
        panic!("Compilation failed, command: {:?}", cmd);
    }
}
