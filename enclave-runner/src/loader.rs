/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult};
use std::os::raw::c_void;
use std::path::Path;
use std::{arch, str};

use failure::{Error, ResultExt};

#[cfg(feature = "crypto-openssl")]
use openssl::{
    hash::Hasher,
    pkey::PKey,
};

use sgx_isa::{Attributes, AttributesFlags, Miscselect, Sigstruct};
use sgxs::crypto::{SgxHashOps, SgxRsaOps};
use sgxs::loader::{Load, MappingInfo, Tcs};
use sgxs::sigstruct::{self, EnclaveHash, Signer};

use crate::tcs::DebugBuffer;
use crate::usercalls::UsercallExtension;
use crate::{Command, Library};

enum EnclaveSource<'a> {
    Path(&'a Path),
    File(File),
    Data(&'a [u8]),
}

impl<'a> EnclaveSource<'a> {
    fn try_clone(&self) -> Option<Self> {
        match *self {
            EnclaveSource::Path(path) => Some(EnclaveSource::Path(path)),
            EnclaveSource::Data(data) => Some(EnclaveSource::Data(data)),
            EnclaveSource::File(_) => None,
        }
    }
}

impl<'a> Read for EnclaveSource<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if let &mut EnclaveSource::Path(path) = self {
            let file = File::open(path)?;
            *self = EnclaveSource::File(file);
        }

        match *self {
            EnclaveSource::File(ref mut file) => file.read(buf),
            EnclaveSource::Data(ref mut data) => data.read(buf),
            EnclaveSource::Path(_) => unreachable!(),
        }
    }
}

pub struct EnclaveBuilder<'a> {
    enclave: EnclaveSource<'a>,
    signature: Option<Sigstruct>,
    attributes: Option<Attributes>,
    miscselect: Option<Miscselect>,
    usercall_ext: Option<Box<dyn UsercallExtension>>,
    load_and_sign: Option<Box<dyn FnOnce(Signer) -> Result<Sigstruct, Error>>>,
    hash_enclave: Option<Box<dyn FnOnce(&mut EnclaveSource<'_>) -> Result<EnclaveHash, Error>>>,
    forward_panics: bool,
    cmd_args: Option<Vec<Vec<u8>>>,
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

// Erased here refers to Type Erasure
#[derive(Debug)]
pub(crate) struct ErasedTcs {
    address: *mut c_void,
    tcs: Box<dyn Tcs>,
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

impl<'a> EnclaveBuilder<'a> {
    pub fn new(enclave_path: &'a Path) -> EnclaveBuilder<'a> {
        Self::new_with_source(EnclaveSource::Path(enclave_path))
    }

    pub fn new_from_memory(enclave_data: &'a [u8]) -> EnclaveBuilder<'a> {
        Self::new_with_source(EnclaveSource::Data(enclave_data))
    }

    fn new_with_source(enclave: EnclaveSource<'a>) -> EnclaveBuilder<'a> {
        let mut ret = EnclaveBuilder {
            enclave,
            attributes: None,
            miscselect: None,
            signature: None,
            usercall_ext: None,
            load_and_sign: None,
            hash_enclave: None,
            forward_panics: false,
            cmd_args: None,
        };

        let _ = ret.coresident_signature();

        #[cfg(feature = "crypto-openssl")]
        ret.with_dummy_signature_signer::<Hasher, _, _, _, _>(|der| {
            PKey::private_key_from_der(der).unwrap().rsa().unwrap()
        });

        ret
    }

    fn generate_dummy_signature(&mut self) -> Result<Sigstruct, Error> {
        fn xgetbv0() -> u64 {
            unsafe { arch::x86_64::_xgetbv(0) }
        }

        let mut enclave = self.enclave.try_clone().unwrap();
        let hash = match self.hash_enclave.take() {
            Some(f) => f(&mut enclave)?,
            None => return Err(format_err!("either compile with default features or use with_dummy_signature_signer()"))
        };
        let mut signer = Signer::new(hash);

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

        match self.load_and_sign.take() {
            Some(f) => f(signer),
            None => Err(format_err!("either compile with default features or use with_dummy_signature_signer()"))
        }
    }

    pub fn dummy_signature(&mut self) -> &mut Self {
        self.signature = None;
        self
    }

    /// Use custom implemetations of [`SgxHashOps`] and [`SgxRsaOps`] for producing dummy signature.
    ///
    /// The hasher is specified through type parameter `H`, and the signer through `S`.
    /// `load_key` is used to parse an RSA private key in DER format and should return a type `T`
    /// that implements `AsRef<S>` where `S` is a type that implements [`SgxRsaOps`]. `E` is the
    /// associated `Error` type of `S` when implementing [`SgxRsaOps`].
    ///
    /// [`SgxHashOps`]: ../sgxs/crypto/trait.SgxHashOps.html
    /// [`SgxRsaOps`]: ../sgxs/crypto/trait.SgxRsaOps.html
    pub fn with_dummy_signature_signer<H, S, F, E, T>(&mut self, load_key: F)
    where
        H: SgxHashOps,
        E: std::error::Error + Send + Sync + 'static,
        S: SgxRsaOps<Error = E>,
        T: AsRef<S>,
        F: 'static + FnOnce(&[u8]) -> T,
    {
        self.load_and_sign = Some(Box::new(move |signer| {
            let key = load_key(include_bytes!("dummy.key"));
            signer.sign::<_, H>(key.as_ref()).map_err(|e| e.into())
        }));
        self.hash_enclave = Some(Box::new(|stream| {
            EnclaveHash::from_stream::<_, H>(stream)
        }));
    }

    pub fn coresident_signature(&mut self) -> IoResult<&mut Self> {
        if let EnclaveSource::Path(path) = self.enclave {
            let sigfile = path.with_extension("sig");
            self.signature(sigfile)
        } else {
            Err(IoError::new(
                ErrorKind::NotFound,
                "Can't load coresident signature for non-file enclave",
            ))
        }
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

    pub fn usercall_extension<T: Into<Box<dyn UsercallExtension>>>(&mut self, extension: T) {
        self.usercall_ext = Some(extension.into());
    }

    /// Whether to panic the runner if any enclave thread panics.
    /// Defaults to `false`.
    /// Note: If multiple enclaves are loaded, and an enclave with this set to
    /// true panics, then all enclaves handled by this runner will exit because
    /// the runner itself will panic.
    pub fn forward_panics(&mut self, fp: bool) -> &mut Self {
        self.forward_panics = fp;
        self
    }

    /// Adds multiple arguments to pass to enclave's `fn main`.
    /// **NOTE:** This is not an appropriate channel for passing secrets or
    /// security configurations to the enclave.
    ///
    /// **NOTE:** This is only applicable to [`Command`] enclaves.
    /// Adding command arguments and then calling [`build_library`] will cause
    /// a panic.
    ///
    /// [`Command`]: struct.Command.html
    /// [`build_library`]: struct.EnclaveBuilder.html#method.build_library
    pub fn args(&mut self, mut args: Vec<Vec<u8>>) -> &mut Self {
        match self.cmd_args {
            None => self.cmd_args = Some(args),
            Some(ref mut cmd_args) => cmd_args.append(&mut args),
        }
        self
    }

    /// Adds an argument to pass to enclave's `fn main`.
    /// **NOTE:** This is not an appropriate channel for passing secrets or
    /// security configurations to the enclave.
    ///
    /// **NOTE:** This is only applicable to [`Command`] enclaves.
    /// Adding command arguments and then calling [`build_library`] will cause
    /// a panic.
    ///
    /// [`Command`]: struct.Command.html
    /// [`build_library`]: struct.EnclaveBuilder.html#method.build_library
    pub fn arg(&mut self, arg: Vec<u8>) -> &mut Self {
        match self.cmd_args {
            None => self.cmd_args = Some(vec![arg]),
            Some(ref mut cmd_args) => cmd_args.push(arg),
        }
        self
    }

    fn load<T: Load>(
        mut self,
        loader: &mut T,
    ) -> Result<(Vec<ErasedTcs>, *mut c_void, usize, bool), Error> {
        let signature = match self.signature {
            Some(sig) => sig,
            None => self
                .generate_dummy_signature()
                .context("While generating dummy signature")?,
        };
        let attributes = self.attributes.unwrap_or(signature.attributes);
        let miscselect = self.miscselect.unwrap_or(signature.miscselect);
        let mapping = loader.load(&mut self.enclave, &signature, attributes, miscselect)?;
        let forward_panics = self.forward_panics;
        if mapping.tcss.is_empty() {
            unimplemented!()
        }
        Ok((
            mapping.tcss.into_iter().map(ErasedTcs::new).collect(),
            mapping.info.address(),
            mapping.info.size(),
            forward_panics,
        ))
    }

    pub fn build<T: Load>(mut self, loader: &mut T) -> Result<Command, Error> {
        let args = self.cmd_args.take().unwrap_or_default();
        let c = self.usercall_ext.take();
        self.load(loader)
            .map(|(t, a, s, fp)| Command::internal_new(t, a, s, c, fp, args))
    }

    /// Panics if you have previously called [`arg`] or [`args`].
    ///
    /// [`arg`]: struct.EnclaveBuilder.html#method.arg
    /// [`args`]: struct.EnclaveBuilder.html#method.args
    pub fn build_library<T: Load>(mut self, loader: &mut T) -> Result<Library, Error> {
        if self.cmd_args.is_some() {
            panic!("Command arguments do not apply to Library enclaves.");
        }
        let c = self.usercall_ext.take();
        self.load(loader)
            .map(|(t, a, s, fp)| Library::internal_new(t, a, s, c, fp))
    }
}
