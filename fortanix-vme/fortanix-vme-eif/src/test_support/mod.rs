#![cfg(test)]
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::LazyLock;

pub static TEST_BINARY: LazyLock<Vec<u8>> = LazyLock::new(read_test_binary);

fn read_test_binary() -> Vec<u8> {
    let binary_path = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/test_support/hello_world"
    ));
    if !binary_path.exists() {
        let compiler = cc::Build::new()
            .opt_level(0)
            .target("x86_64-unknown-linux-gnu")
            .host("x86_64-unknown-linux-gnu")
            .get_compiler();
        let mut cmd = compiler.to_command();
        let src = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/test_support/hello_world.c"
        );
        cmd.arg(src)
            .args(["-static", "-static-libgcc", "-flto"])
            .args(["-o", binary_path.to_str().expect("Failed to get path str")]);
        let status = cmd.status().expect("Failed to execute C compiler");
        if !status.success() {
            panic!("Compilation failed, command: {:?}", cmd);
        }
    }
    let mut f = File::open(binary_path).expect("Unable to open test binary file");
    let mut data = vec![];
    f.read_to_end(&mut data)
        .expect("Unable to read test binary");
    data
}
