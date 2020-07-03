use failure::Error;

use crate::DetectError;
use crate::interpret::{AesmStatus, KmodStatus};
use winapi::um::winbase::GetFirmwareEnvironmentVariableA;
use winapi::shared::minwindef::DWORD;
use std::ffi::CString;

pub fn rdmsr(_address: u64) -> Result<u64, Error> {
    bail!("RDMSR not implemented on Windows")
}

pub fn read_efi_var(name: &str, guid: &str) -> Result<(Vec<u8>, u32), Error> {
    let mut env: Vec<u8> = vec![0; 1024];
    let name = CString::new(name)?;
    let guid = CString::new(guid)?;
    let attr = 0 as DWORD;
    let ret: DWORD = unsafe {
        GetFirmwareEnvironmentVariableExA(
            name.as_ptr(),
            guid.as_ptr(),
            env.as_mut_ptr() as _,
            env.len() as _,
            attr.as_mut_ptr() as _,
        )
    };
    if ret == 0 {
        return Err(DetectError::EfiVariableError(std::io::Error::last_os_error()).into());
    }
    else {
        env.truncate(ret as usize);
        return Ok((env, attr));
    }
}

pub fn write_efi_var(name: &str, guid: &str, value: Vec<u8>, attributes: u32) -> Result<(), Error> {
    let name = CString::new(name)?;
    let guid = CString::new(guid)?;

    let ret: DWORD = unsafe {
        SetFirmwareEnvironmentVariableExA(
            name.as_ptr(),
            guid.as_ptr(),
            value.as_mut_ptr() as _,
            value.len() as _,
            attributes as _,
        )
    };

    if ret == 0 {
        return Err(DetectError::EfiVariableError(std::io::Error::last_or_error()).into());
    }
    else {
        return Ok(());
    }
}

pub fn aesm_status() -> Result<AesmStatus, Error> {
    bail!("AESM Status not implemented on Windows")
}

pub fn kmod_status() -> Result<KmodStatus, Error> {
    bail!("KMOD Status not implemented on Windows")
}
