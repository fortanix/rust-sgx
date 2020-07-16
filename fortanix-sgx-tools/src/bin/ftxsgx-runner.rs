/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;

#[cfg(unix)]
use std::io::{stderr, Write};

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use failure::{Error, ResultExt};
#[cfg(unix)]
use libc::{c_int, c_void, siginfo_t};
#[cfg(unix)]
use nix::sys::signal;
#[cfg(unix)]
use sgxs_loaders::isgx::Device as IsgxDevice;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as IsgxDevice;

use clap::{App, Arg};

arg_enum!{
    #[derive(PartialEq, Debug)]
    #[allow(non_camel_case_types)]
    pub enum Signature {
        coresident,
        dummy
    }
}

#[cfg(unix)]
fn catch_sigbus() {
    unsafe {
        extern "C" fn handle_bus(_signo: c_int, _info: *mut siginfo_t, _context: *mut c_void) {
            eprintln!("SIGBUS triggered: likely caused by stack overflow in enclave.");
            let _ = stderr().flush();
        }

        let hdl = signal::SigHandler::SigAction(handle_bus);
        let sig_action = signal::SigAction::new(hdl, signal::SaFlags::SA_RESETHAND, signal::SigSet::empty());
        signal::sigaction(signal::SIGBUS, &sig_action).unwrap();
    }
}

fn main() -> Result<(), Error> {
    let args = App::new("ftxsgx-runner")
        .arg(
            Arg::with_name("file")
                .required(true)
        )
        .arg(Arg::with_name("signature")
            .short("s")
            .long("signature")
            .required(false)
            .takes_value(true)
            .possible_values(&Signature::variants()))
        .get_matches();

    let file = args.value_of("file").unwrap();

    let mut device = IsgxDevice::new()
        .context("While opening SGX device")?
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());

    match args.value_of("signature").map(|v| v.parse().expect("validated")) {
        Some(Signature::coresident) => { enclave_builder.coresident_signature().context("While loading coresident signature")?; }
        Some(Signature::dummy) => { enclave_builder.dummy_signature(); },
        None => (),
    }

    let enclave = enclave_builder.build(&mut device).context("While loading SGX enclave")?;

    #[cfg(unix)] catch_sigbus();

    enclave.run().map_err(|e| {
        eprintln!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    })
}
