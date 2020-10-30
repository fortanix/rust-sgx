/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;
use std::sync::Arc;

use failure::Error;
use sgx_isa::PageType;
use sgxs::loader::{Load, MappingInfo};

use crate::MappingInfoDynController;
use crate::loader::{EnclaveBuilder, ErasedTcs};
use crate::usercalls::EnclaveState;
use crate::usercalls::UsercallExtension;
use std::fmt;
use std::os::raw::c_void;
use sgxs::loader::EnclaveControl;

pub struct Library {
    enclave: Arc<EnclaveState>,
    address: *mut c_void,
    size: usize,
}

impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Library")
            .field("address", &self.address)
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Debug)]
pub enum NoEnclaveControl{}

impl EnclaveControl for NoEnclaveControl {
    fn remove_trimmed(&self, _: *const u8, _: usize) -> std::result::Result<(), failure::Error> {
        match *self {}
    }

    fn change_memory_type(&self, _: *const u8, _: usize, _: PageType) -> std::result::Result<(), failure::Error> {
        match *self {}
    }
}

impl MappingInfo for Library {
    type EnclaveControl = NoEnclaveControl;

    fn address(&self) -> *mut c_void {
        self.address
    }

    fn size(&self) -> usize {
        self.size
    }

    fn enclave_controller(&self) -> Option<&NoEnclaveControl> {
        None
    }
}

impl Library {
    pub(crate) fn internal_new<T: MappingInfo>(
        tcss: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        info: T,
        forward_panics: bool,
    ) -> Library where <T as MappingInfo>::EnclaveControl: Sized {
        let address = info.address();
        let size = info.size();
        let enclave_controller: Box<dyn MappingInfoDynController> = Box::new(info);
        Library {
            enclave: EnclaveState::library(tcss, enclave_controller, usercall_ext, forward_panics),
            address,
            size,
        }
    }

    pub fn new<P: AsRef<Path>, L: Load>(enclave_path: P, loader: &mut L) -> Result<Library, Error> 
        where <<L as Load>::MappingInfo as MappingInfo>::EnclaveControl: Sized {
        EnclaveBuilder::new(enclave_path.as_ref()).build_library(loader)
    }

    /// If this library's TCSs are all currently servicing other calls, this
    /// function will block until a TCS becomes available.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the parameters passed-in match what the
    /// enclave is expecting.
    pub unsafe fn call(
        &self,
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    ) -> Result<(u64, u64), Error> {
        EnclaveState::library_entry(&self.enclave, p1, p2, p3, p4, p5)
    }
}
