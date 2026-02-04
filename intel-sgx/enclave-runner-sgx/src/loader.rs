/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::arch::x86_64::{self, CpuidResult};
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult};
use std::marker::PhantomData;
use std::os::raw::c_void;
use std::path::Path;
use std::{arch, str};

use anyhow::{format_err, Context};
use thiserror::Error as ThisError;

#[cfg(feature = "crypto-openssl")]
use openssl::{hash::Hasher, pkey::PKey};

use enclave_runner::platform::{
    CommandConfiguration, EnclaveConfiguration, EnclavePlatform, LibraryConfiguration,
};
use sgx_isa::{Attributes, AttributesFlags, Miscselect, Sigstruct};
use sgxs::crypto::{SgxHashOps, SgxRsaOps};
use sgxs::loader::{Load, MappingInfo, Tcs};
use sgxs::sgxs::PageReader;
use sgxs::sigstruct::{self, EnclaveHash, Signer};

use crate::tcs::DebugBuffer;
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

pub struct EnclaveBuilder<'a, L> {
    enclave: EnclaveSource<'a>,
    signature: Option<Sigstruct>,
    attributes: Option<Attributes>,
    miscselect: Option<Miscselect>,
    load_and_sign: Option<Box<dyn FnOnce(Signer) -> Result<Sigstruct, anyhow::Error>>>,
    hash_enclave:
        Option<Box<dyn FnOnce(&mut EnclaveSource<'_>) -> Result<EnclaveHash, anyhow::Error>>>,
    force_time_usercalls: bool,
    loader: PhantomData<L>,
}

#[derive(Debug, ThisError)]
pub enum EnclavePanic {
    /// The first byte of the debug buffer was 0
    #[error("Enclave panicked.")]
    NoDebugBuf,
    /// The debug buffer could be interpreted as a zero-terminated UTF-8 string
    #[error("Enclave panicked: {}", _0)]
    DebugStr(String),
    /// The first byte of the debug buffer was not 0, but it was also not a
    /// zero-terminated UTF-8 string
    #[error("Enclave panicked: {:?}", _0)]
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
    // This represents a resource so we need to maintain ownership even if not
    // used
    #[allow(dead_code)]
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

impl<'a, L> EnclaveBuilder<'a, L> {
    pub fn new(enclave_path: &'a Path) -> EnclaveBuilder<'a, L> {
        Self::new_with_source(EnclaveSource::Path(enclave_path))
    }

    pub fn new_from_memory(enclave_data: &'a [u8]) -> EnclaveBuilder<'a, L> {
        Self::new_with_source(EnclaveSource::Data(enclave_data))
    }

    fn new_with_source(enclave: EnclaveSource<'a>) -> EnclaveBuilder<'a, L> {
        let mut ret = EnclaveBuilder {
            enclave,
            attributes: None,
            miscselect: None,
            signature: None,
            load_and_sign: None,
            hash_enclave: None,
            force_time_usercalls: true, // By default, keep the old behavior of always doing a usercall on an insecure_time call
            loader: PhantomData,
        };

        let _ = ret.coresident_signature();

        #[cfg(feature = "crypto-openssl")]
        ret.with_dummy_signature_signer::<Hasher, _, _, _, _>(|der| {
            PKey::private_key_from_der(der).unwrap().rsa().unwrap()
        });

        ret
    }

    fn generate_xfrm(max_ssaframesize_in_pages: u32) -> u64 {
        fn cpuid(eax: u32, ecx: u32) -> Option<CpuidResult> {
            #![allow(unused_unsafe)]
            unsafe {
                if eax <= x86_64::__get_cpuid_max(0).0 {
                    Some(x86_64::__cpuid_count(eax, ecx))
                } else {
                    None
                }
            }
        }

        fn xgetbv0() -> u64 {
            unsafe { arch::x86_64::_xgetbv(0) }
        }

        debug_assert_ne!(0, max_ssaframesize_in_pages);
        let xcr0 = xgetbv0();

        // See algorithm of Intel x86 dev manual Chpt 40.7.2.2
        let xfrm = (0..64)
            .map(|bit| {
                let select = 0x1 << bit;

                if bit == 0 || bit == 1 {
                    return select; // Bit 0 and 1 always need to be set
                }

                if xcr0 & select == 0 {
                    return 0;
                }

                let CpuidResult {
                    ebx: base,
                    eax: size,
                    ..
                } = match cpuid(0x0d, bit) {
                    None | Some(CpuidResult { ebx: 0, .. }) => return 0,
                    Some(v) => v,
                };

                if max_ssaframesize_in_pages * 0x1000 < base + size {
                    return 0;
                }

                select
            })
            .fold(0, |xfrm, b| xfrm | b);

        // Intel x86 dev manual Vol 3 Chpt 13.3:
        // "Executing the XSETBV instruction causes a general-protection fault (#GP) if ECX = 0
        // and EAX[17] ≠ EAX[18] (TILECFG and TILEDATA must be enabled together). This implies
        // that the value of XCR0[18:17] is always either 00b or 11b."
        // The enclave entry code executes xrstor, and we may have just cleared bit 18, so we
        // need to correct the invariant
        const XCR0_TILE_BITS: u64 = 0b11 << 17;
        match xfrm & XCR0_TILE_BITS {
            XCR0_TILE_BITS | 0 => xfrm,
            _ => xfrm & !XCR0_TILE_BITS,
        }
    }

    fn generate_dummy_signature(&mut self) -> Result<Sigstruct, anyhow::Error> {
        let mut enclave = self.enclave.try_clone().unwrap();
        let create_info = PageReader::new(&mut enclave)?;
        let mut enclave = self.enclave.try_clone().unwrap();
        let hash = match self.hash_enclave.take() {
            Some(f) => f(&mut enclave)?,
            None => {
                return Err(format_err!(
                    "either compile with default features or use with_dummy_signature_signer()"
                ))
            }
        };
        let mut signer = Signer::new(hash);

        let attributes = self.attributes.unwrap_or_else(|| Attributes {
            flags: AttributesFlags::DEBUG | AttributesFlags::MODE64BIT,
            xfrm: Self::generate_xfrm(create_info.0.ecreate.ssaframesize),
        });
        signer
            .attributes_flags(attributes.flags, !0)
            .attributes_xfrm(attributes.xfrm, !0);

        if let Some(miscselect) = self.miscselect {
            signer.miscselect(miscselect, !0);
        }

        match self.load_and_sign.take() {
            Some(f) => f(signer),
            None => Err(format_err!(
                "either compile with default features or use with_dummy_signature_signer()"
            )),
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
        self.hash_enclave = Some(Box::new(|stream| EnclaveHash::from_stream::<_, H>(stream)));
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

    /// SGXv2 platforms allow enclaves to use the `rdtsc` instruction. This can speed up
    /// performance significantly as enclave no longer need to call out to userspace to request the
    /// current time. Unfortunately, older enclaves are not compatible with new enclave runners.
    /// Also, sometimes the behavior of enclaves always calling out the userspace needs to be
    /// simulated. This setting enforces the old behavior.
    pub fn force_insecure_time_usercalls(&mut self, force_time_usercalls: bool) -> &mut Self {
        self.force_time_usercalls = force_time_usercalls;
        self
    }

    fn load<T: Load>(
        mut self,
        mut loader: T,
        forward_panics: bool,
    ) -> Result<(Vec<ErasedTcs>, *mut c_void, usize, bool, bool), anyhow::Error> {
        let signature = match self.signature {
            Some(sig) => sig,
            None => self
                .generate_dummy_signature()
                .context("While generating dummy signature")?,
        };
        let attributes = self.attributes.unwrap_or(signature.attributes);
        let miscselect = self.miscselect.unwrap_or(signature.miscselect);
        let mapping = loader.load(&mut self.enclave, &signature, attributes, miscselect)?;
        let force_time_usercalls = self.force_time_usercalls;
        if mapping.tcss.is_empty() {
            unimplemented!()
        }
        Ok((
            mapping.tcss.into_iter().map(ErasedTcs::new).collect(),
            mapping.info.address(),
            mapping.info.size(),
            forward_panics,
            force_time_usercalls,
        ))
    }
}

impl<'a, L: Load> EnclavePlatform<enclave_runner::Command> for EnclaveBuilder<'a, L> {
    type Loader = L;

    fn build(
        self,
        loader: L,
        configuration: EnclaveConfiguration,
        cmd_configuration: CommandConfiguration,
    ) -> Result<enclave_runner::Command, anyhow::Error> {
        self.load(loader, configuration.forward_panics)
            .map(|(t, a, s, fp, dti)| {
                Command::internal_new(
                    t,
                    a,
                    s,
                    configuration.stream_router,
                    fp,
                    dti,
                    cmd_configuration,
                )
            })
    }
}

impl<'a, L: Load> EnclavePlatform<enclave_runner::Library> for EnclaveBuilder<'a, L> {
    type Loader = L;

    fn build(
        self,
        loader: L,
        configuration: EnclaveConfiguration,
        _: LibraryConfiguration,
    ) -> Result<enclave_runner::Library, anyhow::Error> {
        self.load(loader, configuration.forward_panics)
            .map(|(t, a, s, fp, dti)| {
                Library::internal_new(t, a, s, configuration.stream_router, fp, dti)
            })
    }
}
