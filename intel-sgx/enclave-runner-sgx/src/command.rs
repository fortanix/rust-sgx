/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use anyhow::Error;
use enclave_runner::platform::CommandConfiguration;
use enclave_runner::stream_router::StreamRouter;
use sgxs::loader::Load;

use crate::loader::{EnclaveBuilder, ErasedTcs};
use crate::usercalls::EnclaveState;
use std::os::raw::c_void;

pub struct Command {
    _private: (),
}

impl Command {
    /// # Panics
    /// Panics if the number of TCSs is 0.
    pub(crate) fn internal_new(
        mut tcss: Vec<ErasedTcs>,
        _address: *mut c_void,
        _size: usize,
        stream_router: Box<dyn StreamRouter>,
        forward_panics: bool,
        force_time_usercalls: bool,
        cmd_configuration: CommandConfiguration,
    ) -> enclave_runner::Command {
        (Box::new(move || {
            let main = tcss.remove(0);

            EnclaveState::main_entry(
                main,
                tcss,
                stream_router,
                forward_panics,
                force_time_usercalls,
                cmd_configuration,
            )
        }) as Box<dyn FnOnce() -> _>)
            .into()
    }

    pub fn new<P: AsRef<Path>, L: Load>(
        enclave_path: P,
        loader: &mut L,
    ) -> Result<enclave_runner::Command, Error> {
        enclave_runner::EnclaveBuilder::new(EnclaveBuilder::new(enclave_path.as_ref()))
            .build(loader)
    }
}
