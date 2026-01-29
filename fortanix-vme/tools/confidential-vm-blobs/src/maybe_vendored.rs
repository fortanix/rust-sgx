//! Utility type for blobs that are either passed in as an argument by a user or vendored

use anyhow::{Context as _, Result};
use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

#[derive(Debug)]
pub enum MaybeVendoredImage {
    External(PathBuf),
    /// Unfortunately `ukify` receives its input as a file, so we store fallback blobs in temporary named
    /// files before passing them
    Vendored(NamedTempFile),
}

impl MaybeVendoredImage {
    pub fn path(&self) -> &Path {
        match self {
            MaybeVendoredImage::External(path_buf) => path_buf,
            MaybeVendoredImage::Vendored(named_temp_file) => named_temp_file.path(),
        }
    }

    /// Load a vendored blob to a temp file and create a instance of `Self` from that
    pub fn from_vendored(blob: &[u8]) -> Result<Self> {
        let temp_file = NamedTempFile::new()
            .and_then(|mut tempfile| tempfile.write_all(blob).map(|_| tempfile))
            .and_then(|mut tempfile| tempfile.flush().map(|_| tempfile))
            .context("failed to write backup kernel image to file")?;
        Ok(MaybeVendoredImage::Vendored(temp_file))
    }
}

impl From<PathBuf> for MaybeVendoredImage {
    fn from(value: PathBuf) -> Self {
        MaybeVendoredImage::External(value)
    }
}
