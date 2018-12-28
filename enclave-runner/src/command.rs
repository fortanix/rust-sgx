/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use failure::Error;
use sgxs::loader::Load;

use loader::{EnclaveBuilder, ErasedTcs};
use usercalls::EnclaveState;

pub struct Command {
    main: ErasedTcs,
    threads: Vec<ErasedTcs>,
}

impl Command {
    /// # Panics
    /// Panics if the number of TCSs is 0.
    pub(crate) fn internal_new(mut tcss: Vec<ErasedTcs>) -> Command {
        let main = tcss.remove(0);
        Command {
            main,
            threads: tcss,
        }
    }

    pub fn new<P: AsRef<Path>, L: Load>(enclave_path: P, loader: &mut L) -> Result<Command, Error> {
        EnclaveBuilder::new(enclave_path.as_ref()).build(loader)
    }

    pub fn run(self) -> Result<(), Error> {
        EnclaveState::main_entry(self.main, self.threads)
    }
}
