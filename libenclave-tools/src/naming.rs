/*
 * Tools for building and linking enclaves using libenclave.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use std::path::{PathBuf,Path};
use std::ffi::OsStr;

/// Returns the linked enclave name given the name for the unlinked static
/// library archive
///
/// Returns `None` if `srclib.file_name()` returns `None`.
///
/// # Panics
///
/// Panics if `srclib.file_name()` is not valid UTF-8
pub fn output_lib_name<S: AsRef<OsStr> + ?Sized, E: AsRef<OsStr> + ?Sized>(srclib: &S, extension: &E) -> Option<PathBuf> {
	let srclib=Path::new(srclib);
	let mut srcname=match srclib.file_name() {
		Some(name) => name.to_str().expect("Input path was not valid UTF-8"),
		None => return None,
	};
	if srcname.starts_with("lib") {
		srcname=&srcname[3..];
	}
	let mut dstlib=srclib.with_file_name(Path::new(srcname));
	dstlib.set_extension(extension);
	Some(dstlib)
}
