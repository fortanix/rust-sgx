/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
extern crate failure;
#[macro_use]
extern crate clap;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use failure::{Error, ResultExt};
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
        .arg(Arg::with_name("enclave-args")
            .long_help("Arguments passed to the enclave. \
                Note that this is not an appropriate channel for passing \
                secrets or security configurations to the enclave.")
            .multiple(true))
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

    enclave_builder.arg(file);
    if let Some(enclave_args) = args.values_of("enclave-args") {
        for a in enclave_args {
            enclave_builder.arg(a);
        }
    }

    let enclave = enclave_builder.build(&mut device).context("While loading SGX enclave")?;

    enclave.run().map_err(|e| {
        eprintln!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    })
}
