use anyhow::Result;
use fortanix_vme_initramfs::FsTree;
use fortanix_vme_initramfs::{Initramfs, ReadSeek};
use std::io::{Cursor, Read, Write};

const RUN_APP_CONTENT: &str = "/bin/app";
const EMPTY_ENV: &str = "";
pub const APP_PATH: &str = "rootfs/bin/app";
pub const ENV_PATH: &str = "env";
pub const CMD_PATH: &str = "cmd";
pub const INIT_PATH: &str = "init";

pub fn build_fs_tree<R: ReadSeek + 'static, S: ReadSeek + 'static>(
    application: R,
    init: S,
) -> FsTree {
    FsTree::new()
        .add_file(ENV_PATH, Box::new(Cursor::new(EMPTY_ENV.as_bytes())))
        .add_file(CMD_PATH, Box::new(Cursor::new(RUN_APP_CONTENT.as_bytes())))
        .add_executable(INIT_PATH, Box::new(init))
        .add_executable(APP_PATH, Box::new(application))
        .add_directory("rootfs/dev")
        .add_directory("rootfs/proc")
        .add_directory("rootfs/run")
        .add_directory("rootfs/sys")
        .add_directory("rootfs/tmp")
}

pub fn build<R: ReadSeek + 'static, S: ReadSeek + 'static, U: Read + Write>(
    application: R,
    init: S,
    output: U,
) -> Result<U> {
    let fs_tree = build_fs_tree(application, init);
    let initramfs = Initramfs::from_fs_tree(fs_tree, output)?;
    Ok(initramfs.into_inner())
}
