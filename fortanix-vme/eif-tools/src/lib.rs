use std::ffi::{OsStr, OsString};
use std::fs::File;

/// Verify that the given path points to a readable file.
pub fn readable_file(path: &OsStr) -> Result<(), OsString> {
    match File::open(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{} while opening file: {}", e, path.to_string_lossy()).into()),
    }
}

/// Verify that the given path points to a readable file of ELF format.
pub fn readable_elf_file(path: &OsStr) -> Result<(), OsString> {
    readable_file(path)?;
    match elf::File::open_path(&path) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{:?} while opening file: {}", e, path.to_string_lossy()).into()),
    }
}
