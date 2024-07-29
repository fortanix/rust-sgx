/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::Error;

/// Write given object in json to given filename under given dir (override existing file).
pub fn write_to_file<T: serde::ser::Serialize>(obj: &T, dir: &str, filename: &str) -> Result<(), Error> {
    let path = Path::new(dir);
    let path = path.join(filename);
    write_to_path(&path, obj)
}

/// Write given object in json to given filename under given dir if file is not exist.
///
/// - Returns `Ok(None)` if file already exist.
/// - Returns `Ok(Some(filename))` if succeed to write to new file.
pub fn write_to_file_if_not_exist<T: serde::ser::Serialize>(
    obj: &T,
    dir: &str,
    filename: &str,
) -> Result<Option<PathBuf>, Error> {
    let path = Path::new(dir);
    let path = path.join(filename);
    if path.exists() {
        return Ok(None);
    }
    write_to_path(&path, obj)?;
    Ok(Some(path))
}

fn write_to_path<T: serde::ser::Serialize>(path: &PathBuf, obj: &T) -> Result<(), Error> {
    let mut fp = File::create(&path)?;

    fp.write_all(&serde_json::ser::to_vec(obj).unwrap())
        .map_err(|e| Error::IoError(e))
}

pub fn read_from_file<T: DeserializeOwned>(dir: &str, filename: &str) -> Result<T, Error> {
    let path = Path::new(dir);
    let path = path.join(filename);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let obj = serde_json::from_reader(reader)?;
    Ok(obj)
}
