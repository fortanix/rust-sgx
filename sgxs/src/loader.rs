/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

use abi::{Sigstruct,Einittoken};
use sgxs::SgxsRead;

pub trait Map: Drop {
	fn base_address(&self) -> u64;
	fn tcss(&self) -> &[u64];
}

pub trait Load<'dev> {
	type Mapping: Map + 'dev;
	type Error: ::std::fmt::Debug;
	fn load<'rd, R: SgxsRead + 'rd>(&'dev self, reader: &'rd mut R, sigstruct: Sigstruct, einittoken: Option<Einittoken>) -> Result<Self::Mapping,Self::Error>;
}
