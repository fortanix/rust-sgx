/*
 * Interface to interact with libenclave-based secure enclaves.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use std::mem::transmute;
use std::io::{Read,Write,Error as IoError};
use sgx_isa::{Einittoken,Sigstruct};

pub fn read_sigstruct<R: Read>(reader: &mut R) -> Result<Sigstruct,IoError> {
	let mut buf=[0u8;1808];
	try!(reader.read_exact(&mut buf));
	Ok(unsafe{transmute(buf)})
}

pub fn read_einittoken<R: Read>(reader: &mut R) -> Result<Einittoken,IoError> {
	let mut buf=[0u8;304];
	try!(reader.read_exact(&mut buf));
	Ok(unsafe{transmute(buf)})
}

pub fn write_einittoken<W: Write>(writer: &mut W, token: Einittoken) -> Result<(),IoError> {
	writer.write_all(&mut unsafe{transmute::<_,[u8;304]>(token)})
}
