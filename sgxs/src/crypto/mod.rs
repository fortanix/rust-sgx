/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

use std::io::Write;

pub trait Sha256Digest: Write {
	// Must call as <Sha256 as Sha256Digest>::new()
	fn new() -> Self;
	fn finish(self) -> Vec<u8>;
}

// Should implement Sha256Digest
pub use self::sha256impl::Hasher as Sha256;

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
