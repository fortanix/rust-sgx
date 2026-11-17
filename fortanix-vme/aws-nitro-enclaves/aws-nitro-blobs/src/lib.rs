macro_rules! confidential_blob_path {
    ($suffix: literal) => {
        concat!("/opt/fortanix/confidential-vm-blobs/nitro/", $suffix)
    };
}

pub const KERNEL_PATH: &str = confidential_blob_path!("bzImage");

pub const KERNEL_CONFIG_PATH: &str = confidential_blob_path!("bzImage.config");

pub const CMDLINE_PATH: &str = confidential_blob_path!("cmdline");

pub const INIT_PATH: &str = confidential_blob_path!("init");

pub const NSM_PATH: &str = confidential_blob_path!("nsm.ko");
