/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;
#[macro_use]
extern crate failure;

use std::path::Path;

use aesm_client::AesmClient;
use enclave_runner::Command;
use failure::{Error, ResultExt};
use sgxs_loaders::isgx::{Device as IsgxDevice, DEFAULT_DEVICE_PATH};

fn main() -> Result<(), Error> {
    let mut args = std::env::args_os();
    let cmdname = args.next();
    let file = match args.next() {
        Some(arg) => arg,
        None => {
            let cmdname = cmdname
                .as_ref()
                .and_then(|p| Path::new(p).file_name())
                .map(|p| Path::new(p).display().to_string());
            eprintln!(
                "Usage: {} <ENCLAVE>\n",
                cmdname.unwrap_or("ftxsgx-runner".into())
            ); // extra newline
            bail!("Missing <ENCLAVE> parameter on command line");
        }
    };
    let mut device = IsgxDevice::open(DEFAULT_DEVICE_PATH)
        .context("While opening SGX device")?
        .einittoken_provider(AesmClient::new())
        .build();
    let enclave = Command::new(&file, &mut device).context("While loading SGX enclave")?;
    enclave.run().context("While executing SGX enclave")?;
    Ok(())
}
