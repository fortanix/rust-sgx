/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fmt::Debug;
use std::os::raw::c_void;

use failure::Error;

use abi::{Attributes, Miscselect, PageType, Sigstruct};
use sgxs::SgxsRead;

/// An owned `Tcs` is the only reference to a particular Thread Control
/// Structure (TCS) in an enclave.
pub trait Tcs: 'static + Debug + Send {
    /// The address of the TCS.
    fn address(&self) -> *mut c_void;
}

/// An enclave that's been loaded into memory.
pub trait MappingInfo: 'static + Debug {
    type EnclaveControl: EnclaveControl + ?Sized;

    /// The base address of the enclave.
    fn address(&self) -> *mut c_void;

    /// The size of the enclave (ELRANGE).
    fn size(&self) -> usize;

    /// The controller for the enclave (e.g., add/trim pages)
    fn enclave_controller(&self) -> Option<&Self::EnclaveControl>;
}

pub struct Mapping<T: Load + ?Sized> {
    pub info: T::MappingInfo,
    pub tcss: Vec<T::Tcs>,
}

pub trait EnclaveControl: 'static + Send + Sync + Debug {
    fn trim(&self, addr: *mut u8, size: usize) -> Result<(), Error>;

    fn remove_trimmed(&self, addr: *const u8, size: usize) -> Result<(), Error>;

    fn change_memory_type(&self, addr: *const u8, size: usize, page_type: PageType) -> Result<(), Error>;
}

/// An interface that is able to load an enclave into memory.
pub trait Load {
    type MappingInfo: MappingInfo;
    type Tcs: Tcs;

    /// Load an enclave.
    ///
    /// The enclave will be unloaded once all returned values are dropped.
    fn load<R: SgxsRead>(
        &mut self,
        reader: &mut R,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Error>;
}
