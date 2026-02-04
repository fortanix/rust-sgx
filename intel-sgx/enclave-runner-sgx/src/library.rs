/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;
use std::sync::Arc;

use anyhow::Error;
use enclave_runner::stream_router::StreamRouter;
use sgxs::loader::Load;

use crate::loader::{EnclaveBuilder, ErasedTcs};
use crate::usercalls::EnclaveState;
use std::os::raw::c_void;

/// If this library's TCSs are all currently servicing other calls, the `call`
/// function will block until a TCS becomes available.
pub struct Library {
    _private: (),
}

impl Library {
    pub(crate) fn internal_new(
        tcss: Vec<ErasedTcs>,
        _address: *mut c_void,
        _size: usize,
        stream_router: Box<dyn StreamRouter>,
        forward_panics: bool,
        force_time_usercalls: bool,
    ) -> enclave_runner::Library {
        let enclave =
            EnclaveState::library(tcss, stream_router, forward_panics, force_time_usercalls);
        (Arc::new(move |p1, p2, p3, p4, p5| {
            EnclaveState::library_entry(&enclave, p1, p2, p3, p4, p5)
        }) as Arc<dyn Fn(u64, u64, u64, u64, u64) -> _>)
            .into()
    }

    pub fn new<P: AsRef<Path>, L: Load>(
        enclave_path: P,
        loader: &mut L,
    ) -> Result<enclave_runner::Library, Error> {
        enclave_runner::EnclaveBuilder::new(EnclaveBuilder::new(enclave_path.as_ref()))
            .build(loader)
    }
}
