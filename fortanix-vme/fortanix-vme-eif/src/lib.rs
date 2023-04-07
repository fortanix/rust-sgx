use aws_nitro_enclaves_image_format::generate_build_info;
use aws_nitro_enclaves_image_format::defs::{EifIdentityInfo, EifHeader, EifSectionHeader};
use aws_nitro_enclaves_image_format::utils::EifBuilder;
use serde_json::json;
use sha2::{Digest, Sha512};
use std::io::{self, ErrorKind, Read, Seek, Write};
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

pub struct FtxEif<T> {
    eif: T,
}

impl<T> FtxEif<T> {
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

pub struct SectionIterator<T> {
    reader: T,
}

impl<T> SectionIterator<T> {
    fn new(reader: T) -> SectionIterator<T> {
        SectionIterator {
            reader
        }
    }
}

impl<T: Read> Iterator for SectionIterator<T> {
    type Item = (EifSectionHeader, Vec<u8>);

    fn next(&mut self) -> Option<(EifSectionHeader, Vec<u8>)> {
        fn section_header<T: Read>(reader: &mut T) -> Result<Option<EifSectionHeader>, Error> {
            let mut buff = [0; EifSectionHeader::size()];
            if let Err(e) = reader.read_exact(&mut buff) {
                if e.kind() == ErrorKind::UnexpectedEof {
                    return Ok(None);
                } else {
                    return Err(Error::EifReadError(e));
                }
            }
            let header = EifSectionHeader::from_be_bytes(&mut buff).map_err(|e| Error::EifParseError(e))?;
            Ok(Some(header))
        }

        fn section_content<T: Read>(reader: &mut T, section: &EifSectionHeader) -> Result<Vec<u8>, Error> {
            let mut buff = vec![0u8; section.section_size as usize];
            reader.read_exact(&mut buff).map_err(|e| Error::EifReadError(e))?;
            Ok(buff)
        }

        /*
         *  Eif files are stored as:
         *      +--------------------+ <- 0
         *      |      EifHeader     |
         *     /+--------------------+ <- EifHeader::size()
         *     ||  EifSectionHeader  |
         *  +--|+--------------------+ <- EifHeader::size() + EifSectionHeader::size()
         *  |  ||      <section>     |
         *  |  \+--------------------+ <- EifHeader::size() + EifSectionHeader::size() + section.section_size
         *  |
         *  +-> Any number of sections
         */
        fn section<T: Read>(reader: &mut T) -> Result<Option<(EifSectionHeader, Vec<u8>)>, Error> {
            let header = if let Some(header) = section_header(reader)? {
                header
            } else {
                return Ok(None)
            };
            let content = section_content(reader, &header)?;
            Ok(Some((header, content)))
        }
        section(&mut self.reader).ok().flatten()
    }
}

impl<T: Read> FtxEif<T> {
    /// Parses an eif file and returns the `EifHeader` and an iterator over a tuple of
    /// `EifSectionHeader` and the section content
    /// The AWS image format crate doesn't provide a way to extract these sections easily. This
    /// code should be upstreamed.
    /// https://github.com/aws/aws-nitro-enclaves-image-format/blob/main/src/utils/eif_reader.rs#L85-L209
    pub fn parse(self) -> Result<(EifHeader, SectionIterator<T>), Error> {
        fn header<T: Read>(reader: &mut T) -> Result<EifHeader, Error> {
            let mut buff = [0; EifHeader::size()];
            reader.read_exact(&mut buff).map_err(|e| Error::EifReadError(e))?;
            EifHeader::from_be_bytes(&mut buff).map_err(|e| Error::EifParseError(e))
        }


        let Self { eif: mut reader } = self;
        let header = header(&mut reader)?;
        Ok((header, SectionIterator::new(reader)))
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

    pub fn build<F: Write + Seek>(self, mut output: F) -> Result<FtxEif<F>, Error> {
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

#[cfg(test)]
mod tests {
    use aws_nitro_enclaves_image_format::defs::EifSectionType;
    use std::io::Cursor;
    use super::{Builder, FtxEif};
    use super::initramfs::{Builder as InitramfsBuilder};

    /* Hello world executable created using:
    echo '#include <stdio.h>
    #include <unistd.h>

    void main() {
        int cnt = 0;
        while(1) {
            printf("[%3i] Hello world!\n", cnt);
            sleep(1);
            cnt++;
        }
    }' > main.c
    gcc -o a.out main.c -static -static-libgcc -flto
    */
    const HELLO_WORLD: &'static [u8; 872008] = include_bytes!("../tests/data/hello_world");
    const KERNEL: &'static [u8; 5083088] = include_bytes!("../tests/data/bzImage");
    const KERNEL_CONFIG: &'static str = include_str!("../tests/data/bzImage.config");
    const NSM: &'static [u8; 20504] = include_bytes!("../tests/data/nsm.ko");
    const INIT: &'static [u8; 742968] = include_bytes!("../tests/data/init");
    const CMDLINE: &'static str = include_str!("../tests/data/cmdline");

    #[test]
    fn eif_creation() {
        // Create eif
        let eif = Builder::new(Cursor::new(HELLO_WORLD), Cursor::new(INIT), Cursor::new(NSM), Cursor::new(KERNEL), Cursor::new(KERNEL_CONFIG), CMDLINE)
            .build(Cursor::new(Vec::new()))
            .unwrap()
            .into_inner()
            .into_inner();

        // Parse eif
        let (_header, section_it) = FtxEif::new(Cursor::new(&eif))
            .parse()
            .unwrap();

        let mut initramfs = None;
        let mut sig = None;
        let mut meta = None;
        let mut kernel = None;
        let mut cmdline = None;
        for (section, content) in section_it {
            match section.section_type {
                EifSectionType::EifSectionInvalid => panic!("Invalid section"),
                EifSectionType::EifSectionKernel => {
                    assert_eq!(KERNEL[..], content[..]);
                    assert_eq!(None, kernel.replace(content));
                },
                EifSectionType::EifSectionCmdline => {
                    assert_eq!(CMDLINE.trim(), String::from_utf8(content.clone()).unwrap());
                    assert_eq!(None, cmdline.replace(content));
                },
                EifSectionType::EifSectionRamdisk => {
                    let expected_initramfs = InitramfsBuilder::new(Cursor::new(HELLO_WORLD), Cursor::new(INIT), Cursor::new(NSM))
                        .build(Cursor::new(Vec::new()))
                        .unwrap()
                        .into_inner()
                        .into_inner();
                    assert_eq!(expected_initramfs, content);
                    assert_eq!(None, initramfs.replace(content));
                },
                EifSectionType::EifSectionSignature => {
                    assert_eq!(None, sig.replace(content));
                },
                EifSectionType::EifSectionMetadata => {
                    assert_eq!(None, meta.replace(content));
                }
            }
        }
    }
}
