/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![feature(asm)]
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
use sgxs_loaders::isgx;

fn enclu_eenter(tcs: &mut Tcs) {
    let result: u32;
    unsafe {
        asm!("
		lea aep(%rip),%rcx
		jmp enclu
aep:
		xor %eax,%eax
		jmp post
enclu:
		enclu
post:
"		: "={eax}"(result)
            : "{eax}"(Enclu::EEnter), "{rbx}"(tcs.address())
            : "rcx"
            : "volatile"
        )
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
    let matches = App::new("sgxs-load")
        .about("SGXS loader")
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .requires("le-sgxs")
                .help("Request a debug token"),
        )
        .arg(
            Arg::with_name("device")
                .long("device")
                .takes_value(true)
                .help("Sets the SGX device to use (default: /dev/sgx)"),
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
        )
        .get_matches();

    let dev = matches
        .value_of("device")
        .unwrap_or(isgx::DEFAULT_DEVICE_PATH);
    let mut dev = isgx::Device::open(dev)
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
