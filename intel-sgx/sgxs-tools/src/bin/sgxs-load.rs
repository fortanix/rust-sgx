/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate clap;
extern crate sgx_isa;
extern crate sgxs;
extern crate sgxs_loaders;

use std::fs::File;

use clap::{App, Arg};

use aesm_client::AesmClient;
use sgx_isa::Enclu;
use sgxs::loader::{Load, Tcs};
use sgxs::sigstruct::read as read_sigstruct;

#[cfg(unix)]
use sgxs_loaders::isgx::{Device as SgxDevice, DriverFamily};
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as SgxDevice;


fn enclu_eenter(tcs: &mut dyn Tcs) {
    let result: u32;
    unsafe {
        std::arch::asm!("
            xchg %rbx, {0}
            lea 1f(%rip),%rcx
            jmp 2f
1:
            xor %eax,%eax
            jmp 3f
2:
            enclu
3:
            xchg {0}, %rbx
",
            // rbx is used internally by LLVM and cannot be used as an operand for inline asm (#84658)
            in(reg) tcs.address(),
            inout("eax") Enclu::EEnter as u32 => result,
            lateout("rcx") _,
            options(nostack, att_syntax)
        );
    };

    if result == 0 {
        println!("Got AEX");
    } else if result == (Enclu::EExit as u32) {
        println!("Got EEXIT");
    } else {
        panic!("Invalid return value in EAX! eax={}", result);
    }
}

fn main() {
    let mut matches = App::new("sgxs-load")
        .about("SGXS loader")
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .requires("le-sgxs")
                .help("Request a debug token"),
        )
        .arg(
            Arg::with_name("sgxs")
                .required(true)
                .help("Sets the enclave SGXS file to use"),
        )
        .arg(
            Arg::with_name("sigstruct")
                .required(true)
                .help("Sets the enclave SIGSTRUCT file to use"),
        );
    if cfg!(target_os = "unix") {
        matches = matches.arg(
            Arg::with_name("device")
                .long("device")
                .takes_value(true)
                .help("Sets the SGX device to use (default: /dev/sgx)"),
        );
    }

    let matches = matches.get_matches();

    #[cfg(unix)]
    let device = match matches.value_of("device") {
        Some(dev) => SgxDevice::open(dev, DriverFamily::Montgomery),
        None => SgxDevice::new(),
    };
    #[cfg(windows)]
    let device = SgxDevice::new();

    let mut dev = device
    .unwrap()
    .einittoken_provider(AesmClient::new())
    .build();
    let mut file = File::open(matches.value_of("sgxs").unwrap()).unwrap();
    let sigstruct =
        read_sigstruct(&mut File::open(matches.value_of("sigstruct").unwrap()).unwrap()).unwrap();
    let mut mapping = dev
        .load(
            &mut file,
            &sigstruct,
            sigstruct.attributes,
            sigstruct.miscselect,
        )
        .unwrap();

    let tcs = &mut mapping.tcss[0];
    enclu_eenter(tcs);
}
