use std::io::Cursor;
use fortanix_vme_eif::Builder;

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
const HELLO_WORLD: &'static [u8; 872008] = include_bytes!("data/hello_world");
const KERNEL: &'static [u8; 5083088] = include_bytes!("data/bzImage");
const KERNEL_CONFIG: &'static str = include_str!("data/bzImage.config");
const NSM: &'static [u8; 20504] = include_bytes!("data/nsm.ko");
const INIT: &'static [u8; 742968] = include_bytes!("data/init");
const CMDLINE: &'static str = include_str!("data/cmdline");
const HELLO_WORLD_EIF: &'static [u8; 5751554] = include_bytes!("data/hello_world.eif");

#[test]
fn eif_creation() {
    let _eif = Builder::new(Cursor::new(HELLO_WORLD), Cursor::new(INIT), Cursor::new(NSM), Cursor::new(KERNEL), Cursor::new(KERNEL_CONFIG), CMDLINE.to_string())
        .build(Cursor::new(Vec::new()))
        .unwrap()
        .into_inner()
        .into_inner();
}
