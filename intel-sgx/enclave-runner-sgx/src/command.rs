/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use anyhow::Error;
use sgxs::loader::{Load, MappingInfo};

use crate::loader::{EnclaveBuilder, ErasedTcs};
use crate::usercalls::EnclaveState;
use crate::usercalls::UsercallExtension;
use std::os::raw::c_void;

#[derive(Debug)]
pub struct Command {
    main: ErasedTcs,
    threads: Vec<ErasedTcs>,
    address: usize,
    size: usize,
    usercall_ext: Option<Box<dyn UsercallExtension>>,
    forward_panics: bool,
    force_time_usercalls: bool,
    cmd_args: Vec<Vec<u8>>,
    num_worker_threads: usize,
}

impl MappingInfo for Command {
    fn address(&self) -> *mut c_void {
        self.address as _
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Command {
    /// # Panics
    /// Panics if the number of TCSs is 0.
    pub(crate) fn internal_new(
        mut tcss: Vec<ErasedTcs>,
        address: *mut c_void,
        size: usize,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        forward_panics: bool,
        force_time_usercalls: bool,
        cmd_args: Vec<Vec<u8>>,
        num_worker_threads: usize,
    ) -> Command {
        let main = tcss.remove(0);
        Command {
            main,
            threads: tcss,
            address: address as _,
            size,
            usercall_ext,
            forward_panics,
            force_time_usercalls,
            cmd_args,
            num_worker_threads,
        }
    }

    pub fn new<P: AsRef<Path>, L: Load>(enclave_path: P, loader: &mut L) -> Result<Command, Error> {
        EnclaveBuilder::new(enclave_path.as_ref()).build(loader)
    }

    pub fn run(self) -> Result<(), Error> {
        EnclaveState::main_entry(
            self.main,
            self.threads,
            self.usercall_ext,
            self.forward_panics,
            self.force_time_usercalls,
            self.cmd_args,
            self.num_worker_threads,
        )
    }
}
