use crate::Error;
use fortanix_vme_initramfs::{FsTree, Initramfs};
use std::io::{Cursor, Read, Seek, Write};

const CMD_CONTENT: &str = "/bin/a.out";
const ENV_CONTENT: &str = "";
pub const APP_PATH: &str = "rootfs/bin/a.out";
pub const ENV_PATH: &str = "env";
pub const CMD_PATH: &str = "cmd";
pub const NSM_PATH: &str = "nsm.ko";
pub const INIT_PATH: &str = "init";

pub fn build_fs_tree<
    R: Read + Seek + 'static,
    S: Read + Seek + 'static,
    T: Read + Seek + 'static,
>(
    application: R,
    init: S,
    nsm: T,
) -> FsTree {
    FsTree::new()
        .add_file(ENV_PATH, Box::new(Cursor::new(ENV_CONTENT.as_bytes())))
        .add_file(CMD_PATH, Box::new(Cursor::new(CMD_CONTENT.as_bytes())))
        .add_executable(INIT_PATH, Box::new(init))
        .add_executable(NSM_PATH, Box::new(nsm))
        .add_executable(APP_PATH, Box::new(application))
        .add_directory("rootfs/dev")
        .add_directory("rootfs/proc")
        .add_directory("rootfs/run")
        .add_directory("rootfs/sys")
        .add_directory("rootfs/tmp")
}

pub fn build<
    R: Read + Seek + 'static,
    S: Read + Seek + 'static,
    T: Read + Seek + 'static,
    U: Read + Write,
>(
    application: R,
    init: S,
    nsm: T,
    output: U,
) -> Result<U, Error> {
    let fs_tree = build_fs_tree(application, init, nsm);
    let initramfs = Initramfs::<U>::from_fs_tree(fs_tree, output)?;
    // let builder = InitramfsBuilder::new(fs_tree);
    // Ok(builder.build(output)?.into_inner())
    Ok(initramfs.into_inner())
}
