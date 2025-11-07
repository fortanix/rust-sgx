use anyhow::{self, Context};
use std::os::unix::fs;
use std::path::{Path, PathBuf};

pub fn create_symlink(src: &String, dst_dir: &mut PathBuf) -> anyhow::Result<()> {
    let path = Path::new(src);
    let filename = path
        .file_name()
        .with_context(|| format!("unable to get filename from {}", src))?;
    dst_dir.push(filename);
    if dst_dir.exists() {
        std::fs::remove_file(&mut *dst_dir)?;
    }
    fs::symlink(path, &mut *dst_dir)?;
    dst_dir.pop();
    Ok(())
}
