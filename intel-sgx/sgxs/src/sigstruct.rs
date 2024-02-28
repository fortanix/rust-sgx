/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{Read, Result as IoResult, Write};

use failure::Error;
use time::OffsetDateTime;
use time::macros::format_description;

use abi::{SIGSTRUCT_HEADER1, SIGSTRUCT_HEADER2};
pub use abi::{Attributes, AttributesFlags, Miscselect, Sigstruct};
use crypto::{Hash, SgxHashOps, SgxRsaOps, SgxRsaPubOps};
use sgxs::{copy_measured, SgxsRead};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnclaveHash {
    hash: Hash,
}

impl EnclaveHash {
    pub fn new(hash: Hash) -> Self {
        EnclaveHash { hash }
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn from_stream<R: SgxsRead, H: SgxHashOps>(stream: &mut R) -> Result<Self, Error> {
        struct WriteToHasher<H> {
            hasher: H,
        }

        impl<H: SgxHashOps> Write for WriteToHasher<H> {
            fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
                self.hasher.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> IoResult<()> {
                Ok(())
            }
        }

        let mut out = WriteToHasher { hasher: H::new() };
        copy_measured(stream, &mut out)?;
        Ok(Self::new(out.hasher.finish()))
    }
}

/// # Panics
///
/// Panics if key is not 3072 bits. Panics if the public exponent of key is not 3.
pub fn verify<K: SgxRsaOps, H: SgxHashOps>(sig: &Sigstruct, key: &K) -> Result<(), K::Error> {
    Signer::check_key(key);
    key.verify_sha256_pkcs1v1_5(&sig.signature[..], Signer::sighash::<H>(sig))
}

#[derive(Clone, Debug)]
pub struct Signer {
    date: u32,
    swdefined: u32,
    miscselect: Miscselect,
    miscmask: u32,
    attributes: Attributes,
    attributemask: [u64; 2],
    isvprodid: u16,
    isvsvn: u16,
    enclavehash: EnclaveHash,
}

impl Signer {
    /// Create a new `Signer` with default attributes (64-bit, XFRM: `0x3`) and
    /// today's date.
    pub fn new(enclavehash: EnclaveHash) -> Signer {
        let format = format_description!("[Year][month][day]");
        // Unfortunately `OffsetDateTime::now_local()` doesn't work inside an SGX enclave
        let now = OffsetDateTime::now_utc()
            .format(&format)
            .unwrap()
            .to_string();

        Signer {
            date: u32::from_str_radix(&now, 16).unwrap(),
            swdefined: 0,
            miscselect: Miscselect::default(),
            miscmask: !0,
            attributes: Attributes {
                flags: abi::AttributesFlags::MODE64BIT,
                xfrm: 0x3,
            },
            attributemask: [!abi::AttributesFlags::DEBUG.bits(), !0x3],
            isvprodid: 0,
            isvsvn: 0,
            enclavehash,
        }
    }

    fn check_key<K: SgxRsaOps>(key: &K) {
        if key.len() != 3072 {
            panic!("Key size is not 3072 bits");
        }
        if key.e() != [3] {
            panic!("Key public exponent is not 3");
        }
    }

    fn sighash<H: SgxHashOps>(sig: &Sigstruct) -> Hash {
        let mut hasher = H::new();
        let data = sig.signature_data();
        hasher.update(data.0);
        hasher.update(data.1);
        hasher.finish()
    }

    pub fn unsigned_hash<H: SgxHashOps>(&self) -> Hash {
        let sig = Self::unsigned_sig(self);

        Self::sighash::<H>(&sig)
    }

    pub fn unsigned_sig(&self) -> Sigstruct {
        let sig = Sigstruct {
            header: SIGSTRUCT_HEADER1,
            vendor: 0,
            date: self.date,
            header2: SIGSTRUCT_HEADER2,
            swdefined: self.swdefined,
            _reserved1: [0; 84],
            modulus: [0; 384],
            exponent: 3,
            signature: [0; 384],
            miscselect: self.miscselect,
            miscmask: self.miscmask,
            _reserved2: [0; 20],
            attributes: self.attributes,
            attributemask: self.attributemask,
            enclavehash: self.enclavehash.hash,
            _reserved3: [0; 32],
            isvprodid: self.isvprodid,
            isvsvn: self.isvsvn,
            _reserved4: [0; 12],
            q1: [0; 384],
            q2: [0; 384],
        };

        sig
    }

    /// # Panics
    ///
    /// Panics if key is not 3072 bits. Panics if the public exponent of key is not 3.
    pub fn sign<K: SgxRsaOps, H: SgxHashOps>(self, key: &K) -> Result<Sigstruct, K::Error> {
        Self::check_key(key);

        let mut sig = Self::unsigned_sig(&self);

        let (s, q1, q2) = key.sign_sha256_pkcs1v1_5_with_q1_q2(Self::sighash::<H>(&sig))?;
        let n = key.n();

        // Pad to 384 bytes
        (&mut sig.modulus[..]).write_all(&n).unwrap();
        (&mut sig.signature[..]).write_all(&s).unwrap();
        (&mut sig.q1[..]).write_all(&q1).unwrap();
        (&mut sig.q2[..]).write_all(&q2).unwrap();

        Ok(sig)
    }

    /// Adds a signature from raw bytes. This is used to add a signature
    /// generated in an out-of-band process outside of sgxs-tools.
    pub fn cat_sign<K: SgxRsaPubOps + SgxRsaOps>(
        &self,
        key: &K,
        mut s_vec: Vec<u8>,
    ) -> Result<Sigstruct, <K as SgxRsaPubOps>::Error> {
        Self::check_key(key);

        let mut sig = Self::unsigned_sig(&self);
        let (q1, q2) = key.calculate_q1_q2(&s_vec)?;

        // The signature is read in as big-endian. It must be little-endian for
        // the sigstruct.
        s_vec.reverse();

        let n = key.n();

        (&mut sig.modulus[..]).write_all(&n).unwrap();
        (&mut sig.signature[..]).write_all(&s_vec).unwrap();
        (&mut sig.q1[..]).write_all(&q1).unwrap();
        (&mut sig.q2[..]).write_all(&q2).unwrap();

        Ok(sig)
    }

    pub fn date(&mut self, year: u16, month: u8, day: u8) -> &mut Self {
        // could be faster with manual BCD conversion
        self.date = u32::from_str_radix(&format!("{:04}{:02}{:02}", year, month, day), 16).unwrap();
        self
    }

    pub fn swdefined(&mut self, swdefined: u32) -> &mut Self {
        self.swdefined = swdefined;
        self
    }

    pub fn isvprodid(&mut self, isvprodid: u16) -> &mut Self {
        self.isvprodid = isvprodid;
        self
    }

    pub fn isvsvn(&mut self, isvsvn: u16) -> &mut Self {
        self.isvsvn = isvsvn;
        self
    }

    pub fn miscselect(&mut self, miscselect: Miscselect, mask: u32) -> &mut Self {
        self.miscselect = miscselect;
        self.miscmask = mask;
        self
    }

    pub fn attributes_flags(&mut self, flags: AttributesFlags, mask: u64) -> &mut Self {
        self.attributes.flags = flags;
        self.attributemask[0] = mask;
        self
    }

    pub fn attributes_xfrm(&mut self, xfrm: u64, mask: u64) -> &mut Self {
        self.attributes.xfrm = xfrm;
        self.attributemask[1] = mask;
        self
    }

    pub fn enclavehash(&mut self, hash: EnclaveHash) -> &mut Self {
        self.enclavehash = hash;
        self
    }
}

pub fn read<R: Read>(reader: &mut R) -> IoResult<Sigstruct> {
    let mut buf = [0u8; 1808];
    reader.read_exact(&mut buf)?;
    Sigstruct::try_copy_from(&buf).ok_or_else(|| unreachable!())
}

#[cfg(test)]
mod tests {
    use super::{EnclaveHash, Signer};

    #[test]
    fn signer() {
        let signer = Signer::new(EnclaveHash::new([0; 32]));
        assert!(signer.date & 0xff <= 0x31); // day
        assert!(signer.date & 0xff00 <= 0x1200); // month
        assert!(signer.date & 0xffff0000 >= 0x20240000); // year
        assert!(signer.date & 0xffff0000 <= 0x20500000);
    }
}
