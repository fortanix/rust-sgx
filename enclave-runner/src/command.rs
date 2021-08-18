/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use failure::Error;
use sgxs::loader::{Load, MappingInfo, EnclaveControl};

use crate::loader::{EnclaveBuilder, ErasedTcs};
use crate::usercalls::EnclaveState;
use crate::usercalls::UsercallExtension;
use crate::MappingInfoDynController;
use std::os::raw::c_void;

#[derive(Debug)]
pub struct Command {
    main: ErasedTcs,
    threads: Vec<ErasedTcs>,
    address: usize,
    size: usize,
    usercall_ext: Option<Box<dyn UsercallExtension>>,
    enclave_controller: Box<dyn MappingInfoDynController>,
    forward_panics: bool,
    cmd_args: Vec<Vec<u8>>,
}

impl MappingInfo for Command {
    type EnclaveControl = dyn EnclaveControl;

    fn address(&self) -> *mut c_void {
        self.address as _
    }

    fn size(&self) -> usize {
        self.size
    }

    fn enclave_controller(&self) -> Option<&dyn EnclaveControl> {
        self.enclave_controller.dyn_controller()
    }
}

impl Command {
    /// # Panics
    /// Panics if the number of TCSs is 0.
    pub(crate) fn internal_new<T: MappingInfo>(
        mut tcss: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        info: T,
        forward_panics: bool,
        cmd_args: Vec<Vec<u8>>,
    ) -> Command where <T as MappingInfo>::EnclaveControl: Sized {
        let main = tcss.remove(0);
        let address = info.address() as _;
        let size = info.size();
        let enclave_controller: Box<dyn MappingInfoDynController> = Box::new(info);
        Command {
            main,
            threads: tcss,
            address,
            size,
            usercall_ext,
            enclave_controller,
            forward_panics,
            cmd_args,
        }
    }

    pub fn new<P: AsRef<Path>, L: Load>(enclave_path: P, loader: &mut L) -> Result<Command, Error>
        where <<L as Load>::MappingInfo as MappingInfo>::EnclaveControl: EnclaveControl,
              <<L as Load>::MappingInfo as MappingInfo>::EnclaveControl: Sized {
        EnclaveBuilder::new(enclave_path.as_ref()).build(loader)
    }

    pub fn run(self) -> Result<(), Error> {
        EnclaveState::main_entry(self.main, self.threads, self.usercall_ext, self.enclave_controller, self.forward_panics, self.cmd_args)
    }
}
