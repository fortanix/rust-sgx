/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::Arc;

use anyhow::Error;

type LibraryFn = Arc<dyn Fn(u64, u64, u64, u64, u64) -> Result<(u64, u64), Error>>;

pub struct Library {
    f: LibraryFn
}

impl From<LibraryFn> for Library {
    fn from(f: LibraryFn) -> Self {
        Library {
            f
        }
    }
}

impl Library {
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
        (self.f)(p1, p2, p3, p4, p5)
    }
}
