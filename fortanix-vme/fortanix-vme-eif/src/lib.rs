use aws_nitro_enclaves_image_format::generate_build_info;
use aws_nitro_enclaves_image_format::defs::EifIdentityInfo;
use aws_nitro_enclaves_image_format::utils::EifBuilder;
use serde_json::json;
use sha2::{Digest, Sha512};
use std::io::{self, Read, Seek, Write};
use tempfile::{self, NamedTempFile};

mod initramfs;
mod error;

pub use error::Error;
use initramfs::{Builder as InitramfsBuilder};

pub struct Builder<R: Read + Seek + 'static, S: Read + Seek + 'static, T: Read + Seek + 'static, U: Read + Seek + 'static, V: Read + Seek + 'static> {
    application: R,
    init: S,
    nsm: T,
    kernel: U,
    kernel_config: V,
    cmdline: String,
}

pub struct FtxEif<T: Read + Write> {
    eif: T,
}

impl<T: Read + Write> FtxEif<T> {
    pub fn new(eif: T) -> Self {
        FtxEif {
            eif
        }
    }

    pub fn into_inner(self) -> T {
        let FtxEif { eif } = self;
        eif
    }
}

impl<R: Read + Seek + 'static, S: Read + Seek + 'static, T: Read + Seek + 'static, U: Read + Seek + 'static, V: Read + Seek + 'static> Builder<R, S, T, U, V> {
    pub fn new(application: R, init: S, nsm: T, kernel: U, kernel_config: V, cmdline: &str) -> Self {
        Builder {
            application,
            init,
            nsm,
            kernel,
            kernel_config,
            cmdline: cmdline.trim().to_string(),
        }
    }

    pub fn build<F: Read + Write>(self, mut output: F) -> Result<FtxEif<F>, Error> {
        let Builder { application, init, nsm, kernel: mut image, kernel_config: mut image_config, cmdline } = self;

        // Unfortunately `aws_nitro_enclaves_image_format::EifBuilder` forces us to have data in
        // files.
        let initramfs = NamedTempFile::new().map_err(|e| Error::InitramfsWriteError(e))?;
        let initramfs = InitramfsBuilder::new(application, init, nsm)
            .build(initramfs)?
            .into_inner();

        let mut kernel = NamedTempFile::new().map_err(|e| Error::KernelWriteError(e))?;
        io::copy(&mut image, &mut kernel).map_err(|e| Error::KernelWriteError(e))?;

        let mut kernel_config = NamedTempFile::new().map_err(|e| Error::KernelConfigWriteError(e))?;
        io::copy(&mut image_config, &mut kernel_config).map_err(|e| Error::KernelConfigWriteError(e))?;
        let kernel_config_path = kernel_config
            .path()
            .as_os_str()
            .to_str()
            .ok_or(Error::eif_identity_info(String::from("Failed to retrieve path to kernel config")))?
            .to_string();

        // Unfortunately it's unclear if this information is required. Using defaults found in
        // https://github.com/aws/aws-nitro-enclaves-image-format/blob/d0d224b8b626db5fcc2d7b685bdd229991bbf0a7/examples/eif_build.rs#L171-L184
        let metadata = EifIdentityInfo {
            img_name: String::from("FtxEnclave"),
            img_version: String::from("0.1"),
            build_info: generate_build_info!(&kernel_config_path).map_err(|e| Error::eif_identity_info(e))?,
            docker_info: json!(null),
            custom_info: json!(null),
        };
        let sign_info = None;
        let hasher = Sha512::new();
        let flags = 0;

        let mut eifbuilder = EifBuilder::new(
            kernel.path(),
            cmdline,
            sign_info,
            hasher,
            flags,
            metadata,
            );
        eifbuilder.add_ramdisk(initramfs.path());
        let mut tmp = NamedTempFile::new().map_err(|e| Error::EifWriteError(e))?;
        eifbuilder.write_to(tmp.as_file_mut());
        tmp.rewind().map_err(|e| Error::EifWriteError(e))?;
        io::copy(&mut tmp, &mut output).map_err(|e| Error::EifWriteError(e))?;
        Ok(FtxEif::new(output))
    }
}
