use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, read_dir};
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

use byteorder::{ReadBytesExt, LE};
use failure::{Error, Fail, ResultExt};

use crate::DetectError;
use crate::interpret::{AesmStatus, KmodStatus};
use winapi::um::winbase::GetFirmwareEnvironmentVariableA;
use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::{LPCSTR, PVOID};

pub fn rdmsr(address: u64) -> Result<u64, Error> {
    bail!("Currently not implemented")
}

pub fn read_efi_var(name: &str, guid: &str) -> Result<Vec<u8>, Error> {
    let mut env: Vec<u8> = vec![0; 1024];
    let ret: DWORD = unsafe {
        GetFirmwareEnvironmentVariableA(
            name.as_ptr() as _,
            guid.as_ptr() as _,
            env.as_mut_ptr() as _,
            env.len() as _
        )
    };
    if ret == 0 {
        return Err(DetectError::EfiVariableError(std::io::Error::last_os_error()).into())
    }
    else {
        return Ok(env);
    }
}

pub fn aesm_status() -> Result<AesmStatus, Error> {
    bail!("Currently not implemented")
}

pub fn kmod_status() -> Result<KmodStatus, Error> {
    bail!("Currently not implemented")
}
