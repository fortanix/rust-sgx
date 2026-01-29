pub const INIT_BLOB: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/init"));

pub const FALLBACK_KERNEL_BLOB: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/blobs/vmlinuz-6.14.0-36-generic"
));
