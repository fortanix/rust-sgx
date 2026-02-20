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
