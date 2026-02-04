// TODO: cannot place in lfs - decide on final versions, store these somewhere and download them
pub mod maybe_vendored;

pub const INIT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/init"));

/// Fallback for the used kernel, specified if the user does not provide one
pub const KERNEL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/blobs/bzImage"
));

/// Fallback for the AMD OVMF firmware, specified if the user does not provide one
pub const AMD_SEV_OVMF: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/OVMF.amdsev.fd"));

/// Fallback for the regular OVMF firmware, specified if the user does not provide one in
/// simulation mode
pub const VANILLA_OVMF: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/OVMF.fd"));

/// Blob for the efi boot stub
pub const EFI_BOOT_STUB: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/blobs/linuxx64.efi.stub"
));
