/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;
use std::sync::Arc;

use failure::Error;
use sgxs::loader::Load;

use loader::{EnclaveBuilder, ErasedTcs};
use usercalls::EnclaveState;

pub struct Library {
    enclave: Arc<EnclaveState>,
}

impl Library {
    pub(crate) fn internal_new(tcss: Vec<ErasedTcs>) -> Library {
        Library {
            enclave: EnclaveState::library(tcss),
        }
    }

    pub fn new<P: AsRef<Path>, L: Load>(enclave_path: P, loader: &mut L) -> Result<Library, Error> {
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
