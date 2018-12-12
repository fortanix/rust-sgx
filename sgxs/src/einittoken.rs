/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use failure::Error;
use std::io::{Read, Result as IoResult};

pub use abi::Einittoken;
use abi::{Attributes, Sigstruct};

pub trait EinittokenProvider {
    /// Obtain an `EINITTOKEN` for the enclave specified by this `SIGSTRUCT`
    /// and `ATTRIBUTES`.
    ///
    /// The provider may maintain a cache and may return results from the cache
    /// if `retry` is `false`. A caching provider should recompute the token if
    /// `retry` is `true`.
    fn token(
        &mut self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        retry: bool,
    ) -> Result<Einittoken, Error>;

    /// Will this provider exhibit different behavior if `retry` is `true`?
    fn can_retry(&self) -> bool;
}

impl<P: EinittokenProvider + 'static> From<P> for Box<dyn EinittokenProvider> {
    fn from(p: P) -> Self {
        Box::new(p)
    }
}

pub fn read<R: Read>(reader: &mut R) -> IoResult<Einittoken> {
    let mut buf = [0u8; 304];
    reader.read_exact(&mut buf)?;
    Einittoken::try_copy_from(&buf).ok_or_else(|| unreachable!())
}
