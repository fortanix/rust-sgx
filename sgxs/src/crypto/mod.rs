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
	use openssl::crypto::hash;

	pub type Hasher = hash::Hasher;

	impl super::Sha256Digest for Hasher {
		fn new() -> Hasher {
			Hasher::new(hash::Type::SHA256)
		}

		fn finish(mut self) -> Vec<u8> {
			Hasher::finish(&mut self)
		}
	}
}

// No rust-crypto version of rsa_impl because rust-crypto doesn't do RSA (yet)
mod rsa_impl {
	use std::io::Read;

	use openssl::crypto::pkey::PKey;
	use openssl::crypto::rsa::RSA;
	use openssl::ssl::error::SslError;
	use openssl::crypto::hash::Type as HashType;
	use openssl::bn::BigNum;

	pub struct RsaPrivateKey {
		pkey: PKey,
		rsa: RSA,
	}

	impl super::RsaPrivateKeyOps for RsaPrivateKey {
		type E = SslError;

		fn new<R: Read>(input: &mut R) -> Result<RsaPrivateKey,SslError> {
			let pkey=try!(PKey::private_key_from_pem(input));
			let rsa=pkey.get_rsa();
			Ok(RsaPrivateKey{pkey:pkey,rsa:rsa})
		}

		fn len(&self) -> usize {
			self.pkey.size()*8
		}

		fn sign_sha256_pkcs1v1_5_with_q1_q2<H: AsRef<[u8]>>(&self, hash: H) -> Result<(Vec<u8>,Vec<u8>,Vec<u8>),Self::E> {
			let mut s_vec=self.pkey.sign_with_hash(hash.as_ref(),HashType::SHA256);
			if s_vec.len()==0 {
				Err(SslError::get())
			} else {
				let s=try!(BigNum::new_from_slice(&s_vec[..]));
				let n=try!(self.rsa.n());
				let s_2=try!(s.checked_sqr());
				let q1=try!(s_2.checked_div(&n));
				let q2=try!(try!(try!(s_2.checked_mul(&s)).checked_sub(&try!(try!(q1.checked_mul(&s)).checked_mul(&n)))).checked_div(&n));
				let mut q1=q1.to_vec();
				let mut q2=q2.to_vec();
				q1.reverse();
				q2.reverse();
				s_vec.reverse();
				Ok((s_vec,q1,q2))
			}
		}

		fn e(&self) -> Result<Vec<u8>,Self::E> {
			self.rsa.e().map(|e|{let mut v=e.to_vec();v.reverse();v})
		}

		fn n(&self) -> Result<Vec<u8>,Self::E> {
			self.rsa.n().map(|n|{let mut v=n.to_vec();v.reverse();v})
		}
	}
}

#[cfg(test)]
mod tests;
