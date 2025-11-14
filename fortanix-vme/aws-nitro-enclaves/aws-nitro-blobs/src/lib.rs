use std::{concat, env};

pub const KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bzImage"));
pub const KERNEL_CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/bzImage.config"));
pub const NSM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/nsm.ko"));
pub const INIT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init"));
pub const CMDLINE: &str = include_str!(concat!(env!("OUT_DIR"), "/cmdline"));
