use std::process::{Command, Stdio};

use anyhow::{anyhow, Context};

macro_rules! confidential_blob_path {
    ($suffix: literal) => {
        concat!("/opt/fortanix/confidential-vm-blobs/", $suffix)
    };
}

pub const INIT_PATH: &str = confidential_blob_path!("init");

/// Fallback for the used kernel, specified if the user does not provide one
pub const KERNEL_PATH: &str = confidential_blob_path!("bzImage");

/// Fallback for the AMD OVMF firmware, specified if the user does not provide one
pub const AMD_SEV_OVMF_PATH: &str = confidential_blob_path!("OVMF.amdsev.fd");

/// Fallback for the regular OVMF firmware, specified if the user does not provide one in
/// simulation mode
pub const VANILLA_OVMF_PATH: &str = "/usr/share/ovmf/OVMF.fd";

/// Blob for the efi boot stub
pub const EFI_BOOT_STUB_PATH: &str = confidential_blob_path!("linuxx64.efi.stub");

const DEPENDENCIES_TO_CHECK: [&str; 2] = ["fortanix-confidential-vm-blobs", "systemd-ukify"];

/// Check installation of confidential-vm-blobs dependencies, returning an error if required
/// dependencies are not installed
///
/// Strictly speaking, we do not require the dependencies to be present if the user does not use
/// any fallback values, but we do so anyway for simplicity.
pub fn check_confidential_vm_blobs_dependencies() -> anyhow::Result<()> {
    for name in DEPENDENCIES_TO_CHECK {
        check_dependency(name)?
    }
    Ok(())
}

pub fn check_dependency(name: &str) -> anyhow::Result<()> {
    let dpkg_cmd = Command::new("dpkg")
        .arg("-l")
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to execute child")?;

    let status = Command::new("grep")
        .arg("-q")
        .arg("^ii")
        .stdin(dpkg_cmd.stdout.context("stdio set on dpkg command")?)
        .stdout(Stdio::piped())
        .status()
        .context("failed to execute child")?;

    if !status.success() {
        Err(anyhow!(
            "package {} not found - install it from the appropriate APT repository",
            name
        ))
    } else {
        Ok(())
    }
}
