/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate clap;

use std::convert::{TryFrom, TryInto};
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::io::{stderr, Write};
use std::path::Path;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use enclave_runner_sgx::EnclaveBuilder as EnclaveBuilderSgx;
use anyhow::Context;
#[cfg(unix)]
use libc::{c_int, c_void, siginfo_t};
#[cfg(unix)]
use nix::sys::signal;
use os_str_bytes::OsStrBytesExt;
#[cfg(unix)]
use sgxs_loaders::isgx::Device as IsgxDevice;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as IsgxDevice;

use clap::{App, Arg};

#[derive(PartialEq, Debug)]
pub enum Signature<'s> {
    Coresident,
    Dummy,
    File(&'s Path),
}

impl<'s> TryFrom<&'s OsStr> for Signature<'s> {
    type Error = OsString;

    fn try_from(s: &'s OsStr) -> Result<Self, Self::Error> {
        if let Some(path) = s.strip_prefix("file=") {
            return Ok(Self::File(Path::new(path)));
        }

        if s == "coresident" {
            Ok(Self::Coresident)
        } else if s == "dummy" {
            Ok(Self::Dummy)
        } else {
            Err("expected coresident, dummy or file=<path>".to_owned().into())
        }
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

fn main() -> Result<(), anyhow::Error> {
    let args = App::new("ftxsgx-runner")
        .before_help("Runs an sgxs file, with support for ftxsgx usercalls. \
            See the Fortanix architecture and elf2sgxs for details.")
        .arg(
            Arg::with_name("file")
                .required(true)
                .help("SGXS file to run")
        )
        .arg(Arg::with_name("signature")
            .short("s")
            .long("signature")
            .long_help("Possible values: coresident, dummy, file=<path>. Defaults to 'coresident' with a fallback to 'dummy' if no coresident signature file is found.")
            .required(false)
            .takes_value(true)
            .validator_os(|s| Signature::try_from(s.as_ref()).map(|_| ())))
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

    let mut enclave_builder = EnclaveBuilderSgx::new(file.as_ref());

    match args.value_of_os("signature").map(|v| v.try_into().expect("validated")) {
        Some(Signature::Coresident) => { enclave_builder.coresident_signature().context("While loading coresident signature")?; }
        Some(Signature::Dummy) => { enclave_builder.dummy_signature(); },
        Some(Signature::File(path)) => { enclave_builder.signature(path).with_context(|| format!("Failed to load signature file '{}'", path.display()))?; },
        None => (),
    }

    let mut enclave_builder = EnclaveBuilder::new(enclave_builder);

    if let Some(enclave_args) = args.values_of("enclave-args") {
        enclave_builder.args(enclave_args);
    }

    let enclave = enclave_builder.build(&mut device).context("While loading SGX enclave")?;

    #[cfg(unix)] catch_sigbus();

    enclave.run().map_err(|e| {
        eprintln!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    })
}
