/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fmt::Debug;
use std::os::raw::c_void;

use failure::Error;

use abi::{Attributes, MiscSelect, SigStruct};
use sgxs::SgxsRead;

/// An owned `Tcs` is the only reference to a particular Thread Control
/// Structure (TCS) in an enclave.
pub trait Tcs: 'static + Debug + Send {
    /// The address of the TCS.
    fn address(&self) -> *mut c_void;
}

/// An enclave that's been loaded into memory.
pub trait MappingInfo: 'static + Debug {
    /// The base address of the enclave.
    fn address(&self) -> *mut c_void;

    /// The size of the enclave (ELRANGE).
    fn size(&self) -> usize;
}

pub struct Mapping<T: Load + ?Sized> {
    pub info: T::MappingInfo,
    pub tcss: Vec<T::Tcs>,
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
        sigstruct: &SigStruct,
        attributes: Attributes,
        miscselect: MiscSelect,
    ) -> Result<Mapping<Self>, Error>;
}
