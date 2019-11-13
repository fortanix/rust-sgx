use failure::Error;

use crate::DetectError;
use crate::interpret::{AesmStatus, KmodStatus};
use winapi::um::winbase::GetFirmwareEnvironmentVariableA;
use winapi::shared::minwindef::DWORD;

pub fn rdmsr(_address: u64) -> Result<u64, Error> {
    bail!("RDMSR not implemented on Windows")
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
        env.truncate(ret as usize);
        return Ok(env);
    }
}

pub fn aesm_status() -> Result<AesmStatus, Error> {
    bail!("AESM Status not implemented on Windows")
}

pub fn kmod_status() -> Result<KmodStatus, Error> {
    bail!("KMOD Status not implemented on Windows")
}
