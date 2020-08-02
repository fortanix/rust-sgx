use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{File, OpenOptions, read_dir};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write, Seek, SeekFrom};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

use byteorder::{ReadBytesExt, LE};
use failure::{Error, Fail, ResultExt};

use crate::DetectError;
use crate::interpret::{AesmStatus, KmodStatus};

pub fn rdmsr(address: u64) -> Result<u64, Error> {
    fn modprobe_msr() -> Result<(), Error> {
        let output = Command::new("modprobe")
            .arg("msr")
            .output()
            .context("Failed executing modprobe")?;
        match output.status.success() {
            true => Ok(()),
            false => bail!("{}", String::from_utf8_lossy(&output.stderr).trim_end()),
        }
    }

    let mut attempt = 0;
    loop {
        attempt += 1;
        let file = File::open("/dev/cpu/0/msr");
        match file {
            Ok(mut f) => {
                f.seek(SeekFrom::Start(address))
                    .context("Failed to read MSR")?;
                return f
                    .read_u64::<LE>()
                    .context("Failed to read MSR")
                    .map_err(Into::into);
            }
            Err(ref e) if attempt == 1 && e.kind() == ErrorKind::NotFound => {
                modprobe_msr().context("Failed to load MSR kernel module")?;
                continue;
            }
            Err(e) => bail!(e.context("Failed to open MSR device")),
        }
    }
}

pub fn read_efi_var(name: &str, guid: &str) -> Result<(Vec<u8>, u32), Error> {
    let fspath = (|| {
        for line in BufReader::new(File::open("/proc/self/mountinfo")?).split(b'\n') {
            let line = line?;
            let mut mountinfo = line.split(|&c| c == b' ');
            if let Some(path) = mountinfo.nth(4) {
                let fs = mountinfo.skip(1).skip_while(|&i| i != b"-").nth(1);
                if fs == Some(b"efivarfs") {
                    return Ok(PathBuf::from(OsString::from_vec(path.into())));
                }
            }
        }
        Err(ErrorKind::NotFound.into())
    })()
    .map_err(|e| Error::from(DetectError::EfiFsError(e)))?;

    (|| {
        let mut file = File::open(fspath.join(&format!("{}-{}", name, guid)))?;
        let mut buf = [0u8; 4];
        file.read_exact(&mut buf)?; // read EFI attributes
        let attr = u32::from_le_bytes(buf);
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        Ok((buf, attr))
    })()
    .map_err(|e| DetectError::EfiVariableError(e).into())
}

pub fn write_efi_var(name: &str, guid: &str, value: Vec<u8>, attributes: u32) -> Result<(), Error> {
    let fspath = (|| {
        for line in BufReader::new(File::open("/proc/self/mountinfo")?).split(b'\n') {
            let line = line?;
            let mut mountinfo = line.split(|&c| c == b' ');
            if let Some(path) = mountinfo.nth(4) {
                let fs = mountinfo.skip(1).skip_while(|&i| i != b"-").nth(1);
                if fs == Some(b"efivarfs") {
                    return Ok(PathBuf::from(OsString::from_vec(path.into())));
                }
            }
        }
        Err(ErrorKind::NotFound.into())
    })()
    .map_err(|e| Error::from(DetectError::EfiFsError(e)))?;

    (|| {
        let mut file = OpenOptions::new().write(true).create(true).open(fspath.join(&format!("{}-{}", name, guid)))?;
        if file.write(&attributes.to_le_bytes())? < 4 {
            return Err(std::io::Error::last_os_error());
        }
        if file.write(&value)? < value.len() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })()
    .map_err(|e| e.into())

}

pub fn aesm_status() -> Result<AesmStatus, Error> {
    let out = Command::new("systemctl")
        .args(&["show", "-p", "LoadState,ActiveState", "aesmd.service"])
        .output()
        .context("Failed to query systemd for aesmd.service")?;

    if !out.status.success() {
        bail!("systemctl exited with {}", out.status);
    }
    let out = String::from_utf8(out.stdout).context("systemctl output")?;
    
    let mut propmap = HashMap::new();
    
    for line in out.lines() {
        debug!("systemd aesmd.service: {}", line);
        let mut it = line.trim_end().splitn(2, "=");
        match (it.next(), it.next()) {
            (Some(k), Some(v)) => {
                if propmap.insert(k, v).is_some() {
                    bail!("Duplicate key in systemctl output: {}", line);
                }
            },
            _ => bail!("Malformed line in systemctl output: {}", line),
        }
    }

    if !propmap.contains_key("LoadState") {
        bail!("Missing key in systemctl output: LoadState")
    }
    if !propmap.contains_key("ActiveState") {
        bail!("Missing key in systemctl output: ActiveState")
    }
    if propmap.len() != 2 {
        bail!("Extra keys in systemctl output: {:#?}", propmap);
    }

    if propmap["ActiveState"] == "active" {
        return Ok(AesmStatus::Running)
    }
    if propmap["LoadState"] != "not-found" {
        return Ok(AesmStatus::Installed)
    }

    let out = Command::new("dpkg-query")
        .args(&["--show", "--showformat=${db:Status-Status}", "libsgx-enclave-common"])
        .output()
        .context("Failed to query dpkg for libsgx-enclave-common")?;

    if !out.status.success() {
        bail!("dpkg exited with {}", out.status);
    }

    debug!("dpkg libsgx-enclave-common: {}", String::from_utf8_lossy(&out.stdout));
    
    if out.stdout == b"installed" {
        warn!("dpkg thinks AESM installed, but systemd thinks it's not");
        return Ok(AesmStatus::Installed)
    } else {
        return Ok(AesmStatus::Absent)
    }
}

pub fn kmod_status() -> Result<KmodStatus, Error> {
    let mut status = KmodStatus::default();
    let module_names = ["sgx", "isgx", "intel_sgx"];

    if let Ok(dir) = read_dir("/sys/module") {
        for entry in dir {
            if let Ok(entry) = entry {
                if let Some(&n) = module_names.iter().find(|n| ***n == entry.file_name()) {
                    status.loaded.push(n.into())
                }
            }
        }
    }

    if status.loaded.is_empty() {
        for line in BufReader::new(File::open("/proc/modules")?).lines() {
            let line = line?;
            let modname = line.split(" ").next().unwrap();
            if let Some(&n) = module_names.iter().find(|n| **n == modname) {
                status.loaded.push(n.into())
            }
        }
    }

    for &n in &module_names {
        if Command::new("modinfo").arg(n).output()?.status.success() {
            status.available.push(n.into());
        }
    }

    Ok(status)
}
