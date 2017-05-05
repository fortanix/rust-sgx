/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use std::io::{Read,Write};

pub trait Sha256Digest: Write {
	// Must call as <Sha256 as Sha256Digest>::new()
	fn new() -> Self;
	fn finish(self) -> Vec<u8>;
}

// Should implement Sha256Digest
pub use self::sha256impl::Hasher as Sha256;

pub trait RsaPrivateKeyOps: Sized {
	type E: ::std::error::Error;
	/// Read an RSA private key in PEM format
	fn new<R: Read>(input: &mut R) -> Result<Self,Self::E>;

	/// Return the number of bits in the RSA key
	fn len(&self) -> usize;

	/// Generate an RSASSA-PKCS1-v1_5 signature over a SHA256 hash. Also
	/// compute
	/// - `q1 = s^2 / n`
	/// - `q2 = (s^3 - q1*s*n) / n`
	/// where `/` is integer division.
	///
	/// Returns `(s,q1,q2)` in little-endian format
	///
	/// ### Panics
	/// Panics if the input length is not 32
	fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(&self, hash: H) -> Result<(Vec<u8>,Vec<u8>,Vec<u8>),Self::E>;

	/// Retrieve the public key in little-endian format
	fn e(&self) -> Result<Vec<u8>,Self::E>;

	/// Retrieve the modulus in little-endian format
	fn n(&self) -> Result<Vec<u8>,Self::E>;
}

pub use self::rsa_impl::RsaPrivateKey;

#[cfg(feature="with-rust-crypto")]
mod sha256impl {
	use std::io::{Write,Result as IoResult};

	use rust_crypto::digest::Digest;
	use rust_crypto::sha2::Sha256;

	struct DigestWriter<D: Digest>(D);

	impl<D: Digest> Write for DigestWriter<D> {
		fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
			self.0.input(buf);
			Ok(buf.len())
		}

		fn flush(&mut self) -> IoResult<()> { Ok(()) }
	}

	pub type Hasher = DigestWriter<Sha256>;

	impl super::Sha256Digest for Hasher {
		fn new() -> Hasher {
			DigestWriter(Sha256::new())
		}

		fn finish(mut self) -> Vec<u8> {
			let mut hash=vec![0u8;32];
			self.0.result(&mut hash);
			hash
		}
	}
}

#[cfg(not(feature="with-rust-crypto"))]
mod sha256impl {
	use openssl::hash;

	pub type Hasher = hash::Hasher;

	impl super::Sha256Digest for Hasher {
		fn new() -> Hasher {
			Hasher::new(hash::MessageDigest::sha256()).expect("failed to create openssl hasher")
		}

		fn finish(mut self) -> Vec<u8> {
			Hasher::finish2(&mut self).expect("failed to finish openssl hasher").to_vec()
		}
	}
}

// No rust-crypto version of rsa_impl because rust-crypto doesn't do RSA (yet)
mod rsa_impl {
	use std::io::Read;

	use openssl::pkey::PKey;
	use openssl::rsa::Rsa;
	use openssl::error::ErrorStack as SslError;
	use openssl::bn::{BigNum, BigNumContext};

	pub struct RsaPrivateKey {
		pkey: PKey,
		rsa: Rsa,
	}

	impl super::RsaPrivateKeyOps for RsaPrivateKey {
		type E = SslError;

		fn new<R: Read>(input: &mut R) -> Result<RsaPrivateKey,SslError> {
			let mut data = Vec::new();
			input.read_to_end(&mut data).expect("failed to read rsa private key file");
			let pkey=try!(PKey::private_key_from_pem(&data));
			let rsa=pkey.rsa()?;
			Ok(RsaPrivateKey{pkey:pkey,rsa:rsa})
		}

		fn len(&self) -> usize {
			self.pkey.bits() as usize
		}

		fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(&self, hash: H) -> Result<(Vec<u8>,Vec<u8>,Vec<u8>),Self::E> {
			use openssl::nid;
			use openssl_sys as ffi;
			use foreign_types::ForeignType;
			use std::iter::repeat;
			use libc::{c_int, c_uint};

			// The following `unsafe` block was copied from `fn sign_with_hash`
			// https://github.com/sfackler/rust-openssl/tree/7515272692ea30ee320667563027f75508f1dc60.
			let mut s_vec = unsafe {
				let rsa = ffi::EVP_PKEY_get1_RSA(self.pkey.as_ptr());
				if rsa.is_null() {
				    panic!("Could not get RSA key for signing");
				}
				let len = ffi::RSA_size(rsa);
				let mut r = repeat(0u8).take(len as usize + 1).collect::<Vec<_>>();

				let mut len = 0;
				let rv = ffi::RSA_sign(nid::SHA256.as_raw(),
				                       hash.as_ref().as_ptr(),
				                       hash.as_ref().len() as c_uint,
				                       r.as_mut_ptr(),
				                       &mut len,
				                       rsa);

				if rv < 0 as c_int {
					vec![]
				} else {
					r.truncate(len as usize);
					r
				}
			};

			if s_vec.len()==0 {
				Err(SslError::get())
			} else {
				let mut ctx = BigNumContext::new()?;
				let s = BigNum::from_slice(&s_vec)?;
				let n = self.rsa.n().expect("could not get rsa.n");
				let mut s_2 = BigNum::new()?;
				s_2.sqr(&s, &mut ctx)?;
				let mut q1 = BigNum::new()?;
				q1.checked_div(&s_2, &n, &mut ctx)?;

				let mut tmp1 = BigNum::new()?;
				tmp1.checked_mul(&s_2, &s, &mut ctx)?;
				let mut tmp2 = BigNum::new()?;
				tmp2.checked_mul(&q1, &s, &mut ctx)?;
				let mut tmp3 = BigNum::new()?;
				tmp3.checked_mul(&tmp2, &n, &mut ctx)?;
				let mut tmp4 = BigNum::new()?;
				tmp4.checked_sub(&tmp1, &tmp3)?;
				let mut q2 = BigNum::new()?;
				q2.checked_div(&tmp4, &n, &mut ctx)?;
				let mut q1=q1.to_vec();
				let mut q2=q2.to_vec();
				q1.reverse();
				q2.reverse();
				s_vec.reverse();
				Ok((s_vec,q1,q2))
			}
		}

		fn e(&self) -> Result<Vec<u8>,Self::E> {
			let e = self.rsa.e().expect("could not get rsa.e");
			let mut v = e.to_vec();
			v.reverse();
			Ok(v)
		}

		fn n(&self) -> Result<Vec<u8>,Self::E> {
			let n = self.rsa.n().expect("could not get rsa.n");
			let mut v = n.to_vec();
			v.reverse();
			Ok(v)
		}
	}
}

#[cfg(test)]
mod tests;
