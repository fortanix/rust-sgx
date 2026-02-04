/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! This module contains types and traits that are intended to be used by
//! implementers of enclave platforms. Regular users of this crate shouldn't
//! need these items.
mod internal;

pub use self::internal::{EnclavePlatform, EnclaveType, EnclaveConfiguration, CommandConfiguration, LibraryConfiguration};
