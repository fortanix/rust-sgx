use std::io::Cursor;
use fortanix_vme_eif::{Builder, FtxEif};

/* Hello world executable created using:
echo '#include <stdio.h>
#include <unistd.h>

void main() {
       int cnt = 0;
       while(1) {
               printf("[%3i] Hello world!\n", cnt);
               sleep(1);
               cnt++;
       }
}' > main.c
gcc -o a.out main.c -static -static-libgcc -flto
*/
const HELLO_WORLD: &[u8] = include_bytes!("data/hello_world");
const KERNEL: &[u8] = include_bytes!("data/bzImage");
const KERNEL_CONFIG: &str = include_str!("data/bzImage.config");
const NSM: &[u8] = include_bytes!("data/nsm.ko");
const INIT: &[u8] = include_bytes!("data/init");
const CMDLINE: &str = include_str!("data/cmdline");

#[test]
fn eif_creation_and_extraction() {
    let name = String::from("TestEnclave");
    let hello_world = Cursor::new(HELLO_WORLD);
    let init = Cursor::new(INIT);
    let nsm = Cursor::new(NSM);
    let kernel = Cursor::new(KERNEL);
    let kernel_config = Cursor::new(KERNEL_CONFIG);
    let eif = Builder::new(name, hello_world, init, nsm, kernel, kernel_config, CMDLINE)
        .build(Cursor::new(Vec::new()))
        .unwrap()
        .into_inner()
        .into_inner();

    let mut eif = FtxEif::new(Cursor::new(eif));
    assert_eq!(eif.application().unwrap(), HELLO_WORLD);
}
