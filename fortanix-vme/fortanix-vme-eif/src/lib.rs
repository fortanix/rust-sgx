#![deny(warnings)]
use aws_nitro_enclaves_image_format::defs::{EifHeader, EifIdentityInfo, EifSectionHeader};
use aws_nitro_enclaves_image_format::generate_build_info;
use aws_nitro_enclaves_image_format::utils::EifBuilder;
use serde_json::json;
use sha2::{Digest, Sha512};
use std::io::{self, Cursor, ErrorKind, Read, Seek, Write};
use std::ops::Deref;
use std::path::Path;
use std::rc::Rc;
use tempfile::{self, NamedTempFile};

mod error;
mod initramfs;

pub mod eif_types {
    pub use aws_nitro_enclaves_image_format::defs::{EifHeader, EifIdentityInfo, EifSectionHeader};
}
pub use aws_nitro_enclaves_image_format::defs::EifSectionType;
pub use error::Error;

use fortanix_vme_initramfs::Initramfs;

/// A builder to create a gzipped cpio archive of an initramfs suitable to create an AWS Nitro
/// Enclave from.
pub struct Builder<
    R: Read + Seek + 'static,
    S: Read + Seek + 'static,
    T: Read + Seek + 'static,
    U: Read + Seek + 'static,
    V: Read + Seek + 'static,
> {
    name: String,
    application: R,
    init: S,
    nsm: T,
    kernel: U,
    kernel_config: V,
    cmdline: String,
}

#[derive(Debug, Clone)]
enum EifPart {
    Header(Rc<EifHeader>),
    SectionHeader(Rc<EifSectionHeader>),
    SectionData(Rc<Vec<u8>>),
}

struct EifPartIterator<T: Read> {
    reader: T,
    part: Option<EifPart>,
}

impl<T: Read> EifPartIterator<T> {
    fn new(reader: T) -> EifPartIterator<T> {
        EifPartIterator { reader, part: None }
    }
}

impl<T: Read> Iterator for EifPartIterator<T> {
    type Item = EifPart;

    fn next(&mut self) -> Option<EifPart> {
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
        fn header<T: Read>(reader: &mut T) -> Result<EifHeader, Error> {
            let mut buff = [0; EifHeader::size()];
            reader.read_exact(&mut buff).map_err(Error::EifReadError)?;
            EifHeader::from_be_bytes(&buff).map_err(Error::EifParseError)
        }

        fn section_header<T: Read>(reader: &mut T) -> Result<Option<EifSectionHeader>, Error> {
            let mut buff = [0; EifSectionHeader::size()];
            if let Err(e) = reader.read_exact(&mut buff) {
                if e.kind() == ErrorKind::UnexpectedEof {
                    return Ok(None);
                } else {
                    return Err(Error::EifReadError(e));
                }
            }
            let header = EifSectionHeader::from_be_bytes(&buff).map_err(Error::EifParseError)?;
            Ok(Some(header))
        }

        fn section_content<T: Read>(
            reader: &mut T,
            section: &EifSectionHeader,
        ) -> Result<Vec<u8>, Error> {
            let mut buff = vec![0u8; section.section_size as usize];
            reader.read_exact(&mut buff).map_err(Error::EifReadError)?;
            Ok(buff)
        }

        match &self.part {
            None => {
                let h = header(&mut self.reader).ok()?;
                self.part = Some(EifPart::Header(Rc::new(h)));
            }
            Some(EifPart::Header(_)) | Some(EifPart::SectionData(_)) => {
                let s = section_header(&mut self.reader).ok()??;
                self.part = Some(EifPart::SectionHeader(Rc::new(s)));
            }
            Some(EifPart::SectionHeader(h)) => {
                let data = section_content(&mut self.reader, h).ok()?;
                self.part = Some(EifPart::SectionData(Rc::new(data)));
            }
        }
        self.part.clone()
    }
}

pub struct SectionIterator<T: Read>(EifPartIterator<T>);

impl<T: Read> Iterator for SectionIterator<T> {
    type Item = (Rc<EifSectionHeader>, Rc<Vec<u8>>);

    fn next(&mut self) -> Option<(Rc<EifSectionHeader>, Rc<Vec<u8>>)> {
        let header = self.0.next()?;
        let data = self.0.next()?;
        match (header, data) {
            (EifPart::SectionHeader(h), EifPart::SectionData(d)) => Some((h, d)),
            _ => None,
        }
    }
}

pub struct FtxEif<T> {
    eif: T,
}

impl<T> FtxEif<T> {
    pub fn new(eif: T) -> Self {
        FtxEif { eif }
    }

    pub fn into_inner(self) -> T {
        let FtxEif { eif } = self;
        eif
    }
}

impl<T: Read + Seek> FtxEif<T> {
    /// Parses an eif file and returns an iterator of its parts
    /// The AWS image format crate doesn't provide a way to extract these sections easily. This
    /// code should be upstreamed.
    /// https://github.com/aws/aws-nitro-enclaves-image-format/blob/main/src/utils/eif_reader.rs#L85-L209
    fn iter(&mut self) -> Result<EifPartIterator<&mut T>, Error> {
        self.eif.rewind().map_err(Error::EifReadError)?;
        Ok(EifPartIterator::new(&mut self.eif))
    }

    fn eif_header_ex(&mut self) -> Result<(Rc<EifHeader>, EifPartIterator<&mut T>), Error> {
        let mut it = self.iter()?;
        let header = it
            .next()
            .map(|h| {
                if let EifPart::Header(header) = h {
                    Ok(header.clone())
                } else {
                    Err(Error::EifParseError(String::from(
                        "Malformed eif file: Expected EifHeader",
                    )))
                }
            })
            .ok_or(Error::EifParseError(String::from(
                "Failed to parse eif header",
            )))??;
        Ok((header, it))
    }

    pub fn eif_header(&mut self) -> Result<Rc<EifHeader>, Error> {
        self.eif_header_ex().map(|(header, _)| header)
    }

    pub fn sections(&mut self) -> Result<SectionIterator<&mut T>, Error> {
        let it = self.eif_header_ex()?.1;
        Ok(SectionIterator(it))
    }

    pub fn application(&mut self) -> Result<Vec<u8>, Error> {
        let initramfs = self
            .sections()?
            .find_map(|(hdr, cnt)| {
                if hdr.section_type == EifSectionType::EifSectionRamdisk {
                    Some(cnt)
                } else {
                    None
                }
            })
            .ok_or(Error::EifParseError(String::from("No ramdisks found")))?;

        let initramfs = Initramfs::from(Cursor::new(initramfs.deref()));
        let app = initramfs.read_entry_by_path(initramfs::APP_PATH)?;
        Ok(app)
    }

    pub fn metadata(&mut self) -> Result<EifIdentityInfo, Error> {
        let metadata = self
            .sections()?
            .find_map(|(header, data)| {
                if header.deref().section_type == EifSectionType::EifSectionMetadata {
                    Some(data)
                } else {
                    None
                }
            })
            .ok_or(Error::EifParseError(String::from(
                "No metadata section found in EIF file",
            )))?;
        serde_json::from_slice(metadata.deref().as_slice()).map_err(Error::MetadataParseError)
    }
}

impl<
        R: Read + Seek + 'static,
        S: Read + Seek + 'static,
        T: Read + Seek + 'static,
        U: Read + Seek + 'static,
        V: Read + Seek + 'static,
    > Builder<R, S, T, U, V>
{
    pub fn new(
        name: String,
        application: R,
        init: S,
        nsm: T,
        kernel: U,
        kernel_config: V,
        cmdline: &str,
    ) -> Self {
        Builder {
            name,
            application,
            init,
            nsm,
            kernel,
            kernel_config,
            cmdline: cmdline.trim().to_string(),
        }
    }

    pub fn build<F: Write + Seek>(self, mut output: F) -> Result<FtxEif<F>, Error> {
        let Builder {
            name,
            application,
            init,
            nsm,
            kernel: mut image,
            kernel_config: mut image_config,
            cmdline,
        } = self;

        // Unfortunately `aws_nitro_enclaves_image_format::EifBuilder` forces us to have data in
        // files.
        let initramfs = NamedTempFile::new().map_err(Error::EifWriteError)?;
        let initramfs = initramfs::build(application, init, nsm, initramfs)?;

        let mut kernel = NamedTempFile::new().map_err(Error::KernelWriteError)?;
        io::copy(&mut image, &mut kernel).map_err(Error::KernelWriteError)?;

        let mut kernel_config = NamedTempFile::new().map_err(Error::KernelConfigWriteError)?;
        io::copy(&mut image_config, &mut kernel_config).map_err(Error::KernelConfigWriteError)?;
        let kernel_config_path = kernel_config
            .path()
            .as_os_str()
            .to_str()
            .ok_or(Error::eif_identity_info(String::from(
                "Failed to retrieve path to kernel config",
            )))?
            .to_string();

        // Unfortunately it's unclear if this information is required. Using defaults found in
        // https://github.com/aws/aws-nitro-enclaves-image-format/blob/d0d224b8b626db5fcc2d7b685bdd229991bbf0a7/examples/eif_build.rs#L171-L184
        let metadata = EifIdentityInfo {
            img_name: name,
            img_version: String::from("0.1"),
            build_info: generate_build_info!(&kernel_config_path)
                .map_err(Error::eif_identity_info)?,
            docker_info: json!(null),
            custom_info: json!(null),
        };
        let sign_info = None;
        let hasher = Sha512::new();
        let flags = 0;

        let mut eifbuilder =
            EifBuilder::new(kernel.path(), cmdline, sign_info, hasher, flags, metadata);
        eifbuilder.add_ramdisk(initramfs.path());
        let mut tmp = NamedTempFile::new().map_err(Error::EifWriteError)?;
        eifbuilder.write_to(tmp.as_file_mut());
        tmp.rewind().map_err(Error::EifWriteError)?;
        io::copy(&mut tmp, &mut output).map_err(Error::EifWriteError)?;
        Ok(FtxEif::new(output))
    }
}

pub struct ReadEifResult<T> {
    pub eif: FtxEif<T>,
    pub metadata: EifIdentityInfo,
}

pub fn read_eif_with_metadata<P: AsRef<Path>>(
    enclave_file_path: P,
) -> Result<ReadEifResult<impl Read + Seek>, Error> {
    let f = std::fs::File::open(enclave_file_path).map_err(Error::EifWriteError)?;
    let mut eif = FtxEif::new(io::BufReader::new(f));
    let metadata = eif.metadata()?;
    Ok(ReadEifResult { eif, metadata })
}

#[cfg(test)]
mod tests {
    use super::{initramfs, Builder, FtxEif};
    use aws_nitro_blobs::{CMDLINE, INIT, KERNEL, KERNEL_CONFIG, NSM};
    use aws_nitro_enclaves_image_format::defs::EifSectionType;
    use fortanix_vme_initramfs::Initramfs;
    use std::io::{Cursor, Seek};
    use std::ops::Deref;
    use test_resources::HELLO_WORLD;

    #[test]
    fn eif_creation() {
        // Create eif
        let name = String::from("enclave");
        let eif = Builder::new(
            name.clone(),
            Cursor::new(HELLO_WORLD),
            Cursor::new(INIT),
            Cursor::new(NSM),
            Cursor::new(KERNEL),
            Cursor::new(KERNEL_CONFIG),
            CMDLINE,
        )
        .build(Cursor::new(Vec::new()))
        .unwrap()
        .into_inner()
        .into_inner();

        // Parse eif
        let mut eif_reader = FtxEif::new(Cursor::new(&eif));
        let mut initramfs = None;
        let mut sig = None;
        let mut meta = None;
        let mut kernel = None;
        let mut cmdline = None;
        for (section, content) in eif_reader.sections().unwrap() {
            match section.section_type {
                EifSectionType::EifSectionInvalid => panic!("Invalid section"),
                EifSectionType::EifSectionKernel => {
                    assert_eq!(KERNEL[..], content[..]);
                    assert_eq!(None, kernel.replace(content));
                }
                EifSectionType::EifSectionCmdline => {
                    assert_eq!(
                        CMDLINE.trim(),
                        String::from_utf8(content.deref().clone()).unwrap()
                    );
                    assert_eq!(None, cmdline.replace(content));
                }
                EifSectionType::EifSectionRamdisk => {
                    let expected_initramfs = initramfs::build(
                        Cursor::new(HELLO_WORLD),
                        Cursor::new(INIT),
                        Cursor::new(NSM),
                        Cursor::new(Vec::new()),
                    )
                    .unwrap()
                    .into_inner();
                    assert_eq!(expected_initramfs, *content);
                    assert_eq!(None, initramfs.replace(content));
                }
                EifSectionType::EifSectionSignature => {
                    assert_eq!(None, sig.replace(content));
                }
                EifSectionType::EifSectionMetadata => {
                    assert_eq!(None, meta.replace(content));
                }
            }
        }
        assert_eq!(eif_reader.metadata().unwrap().img_name, name);
    }

    #[test]
    fn eif_creation_and_extraction() {
        let name = String::from("TestEnclave");
        let hello_world = Cursor::new(HELLO_WORLD);
        let init = Cursor::new(INIT);
        let nsm = Cursor::new(NSM);
        let kernel = Cursor::new(KERNEL);
        let kernel_config = Cursor::new(KERNEL_CONFIG);
        let eif = Builder::new(name, hello_world, init, nsm, kernel, kernel_config, CMDLINE)
            .build(Cursor::new(Vec::new()))
            .unwrap()
            .into_inner()
            .into_inner();
        let mut eif = FtxEif::new(Cursor::new(eif));
        assert_eq!(eif.application().unwrap(), HELLO_WORLD);
    }

    #[test]
    fn initramfs_verification() {
        let output = Cursor::new(Vec::new());
        let initramfs = initramfs::build(
            Cursor::new(HELLO_WORLD),
            Cursor::new(INIT),
            Cursor::new(NSM),
            output,
        )
        .unwrap()
        .into_inner();
        let initramfs = Initramfs::from(Cursor::new(initramfs));
        let fs_tree = initramfs::build_fs_tree(
            Cursor::new(HELLO_WORLD),
            Cursor::new(INIT),
            Cursor::new(NSM),
        );
        let initramfs_blob = initramfs.into_inner().into_inner();
        let mut cursor = Cursor::new(initramfs_blob);
        Initramfs::from(&mut cursor).verify(fs_tree).unwrap();
        cursor.rewind().unwrap();
        Initramfs::from(&mut cursor)
            .read_entry_by_path(initramfs::APP_PATH)
            .unwrap();
    }
}
