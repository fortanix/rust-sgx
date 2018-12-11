/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::{arch, str};

use failure::{Error, ResultExt};

use openssl::hash::Hasher;
use openssl::pkey::PKey;

use sgx_isa::{Attributes, AttributesFlags, Miscselect, Sigstruct};
use sgxs::loader::{Load, Tcs};
use sgxs::sigstruct::{self, EnclaveHash, Signer};

use tcs::DebugBuffer;
use {Command, Library};

pub struct EnclaveBuilder {
    path: PathBuf,
    signature: Option<Sigstruct>,
    attributes: Option<Attributes>,
    miscselect: Option<Miscselect>,
}

#[derive(Debug, Fail)]
pub enum EnclavePanic {
    /// The first byte of the debug buffer was 0
    #[fail(display = "Enclave panicked.")]
    NoDebugBuf,
    /// The debug buffer could be interpreted as a zero-terminated UTF-8 string
    #[fail(display = "Enclave panicked: {}", _0)]
    DebugStr(String),
    /// The first byte of the debug buffer was not 0, but it was also not a
    /// zero-terminated UTF-8 string
    #[fail(display = "Enclave panicked: {:?}", _0)]
    DebugBuf(Vec<u8>),
}

impl From<DebugBuffer> for EnclavePanic {
    fn from(buf: DebugBuffer) -> EnclavePanic {
        if buf[0] == 0 {
            EnclavePanic::NoDebugBuf
        } else {
            match str::from_utf8(buf.split(|v| *v == 0).next().unwrap()) {
                Ok(s) => EnclavePanic::DebugStr(s.to_owned()),
                Err(_) => EnclavePanic::DebugBuf(buf.to_vec()),
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ErasedTcs {
    address: *mut c_void,
    tcs: Box<Tcs>,
}

// Would be `send` if we didn't cache the raw pointer address
unsafe impl Send for ErasedTcs {}

impl ErasedTcs {
    fn new<T: Tcs + 'static>(tcs: T) -> ErasedTcs {
        ErasedTcs {
            address: tcs.address(),
            tcs: Box::new(tcs),
        }
    }
}

impl Tcs for ErasedTcs {
    fn address(&self) -> *mut c_void {
        self.address
    }
}

impl EnclaveBuilder {
    pub fn new<P: AsRef<Path>>(enclave_path: P) -> EnclaveBuilder {
        let mut ret = EnclaveBuilder {
            path: enclave_path.as_ref().to_owned(),
            attributes: None,
            miscselect: None,
            signature: None,
        };

        let _ = ret.coresident_signature();

        ret
    }

    fn generate_dummy_signature(&self) -> Result<Sigstruct, Error> {
        fn xgetbv0() -> u64 {
            unsafe { arch::x86_64::_xgetbv(0) }
        }

        let mut file = File::open(&self.path)?;
        let mut signer = Signer::new(EnclaveHash::from_stream::<_, Hasher>(&mut file)?);

        let attributes = self.attributes.unwrap_or_else(|| Attributes {
            flags: AttributesFlags::DEBUG | AttributesFlags::MODE64BIT,
            xfrm: xgetbv0(),
        });
        signer
            .attributes_flags(attributes.flags, !0)
            .attributes_xfrm(attributes.xfrm, !0);

        if let Some(miscselect) = self.miscselect {
            signer.miscselect(miscselect, !0);
        }

        let key = PKey::private_key_from_der(include_bytes!("dummy.key")).unwrap();
        Ok(signer.sign::<_, Hasher>(&*key.rsa().unwrap())?)
    }

    pub fn dummy_signature(&mut self) -> &mut Self {
        self.signature = None;
        self
    }

    pub fn coresident_signature(&mut self) -> IoResult<&mut Self> {
        let sigfile = self.path.with_extension("sig");
        self.signature(sigfile)
    }

    pub fn signature<P: AsRef<Path>>(&mut self, path: P) -> IoResult<&mut Self> {
        let mut file = File::open(path)?;
        self.signature = Some(sigstruct::read(&mut file)?);
        Ok(self)
    }

    pub fn sigstruct(&mut self, sigstruct: Sigstruct) -> &mut Self {
        self.signature = Some(sigstruct);
        self
    }

    pub fn attributes(&mut self, attributes: Attributes) -> &mut Self {
        self.attributes = Some(attributes);
        self
    }

    pub fn miscselect(&mut self, miscselect: Miscselect) -> &mut Self {
        self.miscselect = Some(miscselect);
        self
    }

    fn load<T: Load>(self, loader: &mut T) -> Result<Vec<ErasedTcs>, Error> {
        enum OpenAndRead<'a> {
            Unopened(&'a Path),
            Reading(File),
        }

        impl<'a> Read for OpenAndRead<'a> {
            fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
                if let &mut OpenAndRead::Unopened(path) = self {
                    let file = File::open(path)?;
                    *self = OpenAndRead::Reading(file);
                }

                if let &mut OpenAndRead::Reading(ref mut file) = self {
                    file.read(buf)
                } else {
                    unreachable!()
                }
            }
        }

        let signature = match self.signature {
            Some(sig) => sig,
            None => self
                .generate_dummy_signature()
                .context("While generating dummy signature")?,
        };
        let attributes = self.attributes.unwrap_or(signature.attributes);
        let miscselect = self.miscselect.unwrap_or(signature.miscselect);
        let mapping = loader.load(
            &mut OpenAndRead::Unopened(&self.path),
            &signature,
            attributes,
            miscselect,
        )?;
        if mapping.tcss.is_empty() {
            unimplemented!()
        }
        Ok(mapping.tcss.into_iter().map(ErasedTcs::new).collect())
    }

    pub fn build<T: Load>(self, loader: &mut T) -> Result<Command, Error> {
        Ok(Command::internal_new(self.load(loader)?))
    }

    pub fn build_library<T: Load>(self, _loader: &mut T) -> Result<Library, Error> {
        unimplemented!()
    }
}
