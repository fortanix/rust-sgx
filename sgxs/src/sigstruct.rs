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

use std;
use std::io::{self,Write};

use time;

use abi::{self,Sigstruct,Attributes,AttributesFlags,Miscselect,SIGSTRUCT_HEADER1,SIGSTRUCT_HEADER2};
use crypto::{Sha256Digest,Sha256,RsaPrivateKeyOps,RsaPrivateKey};

#[derive(Clone,Debug)]
pub struct Signer {
	date:          u32,
	swdefined:     u32,
	miscselect:    Miscselect,
	miscmask:      u32,
	attributes:    Attributes,
	attributemask: [u64; 2],
	isvprodid:     u16,
	isvsvn:        u16,
	enclavehash:   Option<[u8; 32]>,
}

impl Signer {
	/// Create a new `Signer` with default attributes (64-bit, XFRM: `0x3`) and
	/// today's date.
	pub fn new() -> Signer {
		Signer {
			date:          u32::from_str_radix(&time::strftime("%Y%m%d",&time::now()).unwrap(),16).unwrap(),
			swdefined:     0,
			miscselect:    Miscselect::default(),
			miscmask:      !0,
			attributes:    Attributes{flags:abi::attributes_flags::MODE64BIT,xfrm:0x3},
			attributemask: [!abi::attributes_flags::DEBUG.bits(),!0x3],
			isvprodid:     0,
			isvsvn:        0,
			enclavehash:   None,
		}
	}

	/// # Panics
	///
	/// Panics if called before `enclavehash` is called. Panics if key is not
	/// 3072 bits. Panics if the public exponent of key is not 3.
	pub fn sign(self, key: &RsaPrivateKey) -> Result<Sigstruct,<RsaPrivateKey as RsaPrivateKeyOps>::E> {
		if key.len()!=3072 {
			panic!("Key size is not 3072 bits");
		}
		if key.e().unwrap()!=[3] {
			panic!("Key public exponent is not 3");
		}

		let mut sig=Sigstruct {
			header:        SIGSTRUCT_HEADER1,
			vendor:        0,
			date:          self.date,
			header2:       SIGSTRUCT_HEADER2,
			swdefined:     self.swdefined,
			_reserved1:    [0;84],
			modulus:       [0;384],
			exponent:      3,
			signature:     [0;384],
			miscselect:    self.miscselect,
			miscmask:      self.miscmask,
			_reserved2:    [0;20],
			attributes:    self.attributes,
			attributemask: self.attributemask,
			enclavehash:   self.enclavehash.expect("Must set hash before calling sign"),
			_reserved3:    [0;32],
			isvprodid:     self.isvprodid,
			isvsvn:        self.isvsvn,
			_reserved4:    [0;12],
			q1:            [0;384],
			q2:            [0;384],
		};

		let sighash;
		{
			let sig_buf=unsafe{std::slice::from_raw_parts(&sig as *const _ as *const u8,std::mem::size_of::<Sigstruct>())};
			let mut hasher=<Sha256 as Sha256Digest>::new();
			hasher.write(&sig_buf[0..128]).unwrap();
			hasher.write(&sig_buf[900..1028]).unwrap();
			sighash=hasher.finish();
		}

		let (s,q1,q2)=try!(key.sign_sha256_pkcs1v1_5_with_q1_q2(&sighash));
		let n=key.n().unwrap();

		(&mut sig.modulus[..]).write_all(&n).unwrap();
		(&mut sig.signature[..]).write_all(&s).unwrap();
		(&mut sig.q1[..]).write_all(&q1).unwrap();
		(&mut sig.q2[..]).write_all(&q2).unwrap();

		Ok(sig)
	}

	pub fn date(&mut self, year: u16, month: u8, day: u8) -> &mut Self {
		// could be faster with manual BCD conversion
		self.date=u32::from_str_radix(&format!("{:04}{:02}{:02}",year,month,day),16).unwrap();
		self
	}

	pub fn swdefined(&mut self, swdefined: u32) -> &mut Self {
		self.swdefined=swdefined;
		self
	}

	pub fn isvprodid(&mut self, isvprodid: u16) -> &mut Self {
		self.isvprodid=isvprodid;
		self
	}

	pub fn isvsvn(&mut self, isvsvn: u16) -> &mut Self {
		self.isvsvn=isvsvn;
		self
	}

	pub fn miscselect(&mut self, miscselect: Miscselect, mask: u32) -> &mut Self {
		self.miscselect=miscselect;
		self.miscmask=mask;
		self
	}

	pub fn attributes_flags(&mut self, flags: AttributesFlags, mask: u64) -> &mut Self {
		self.attributes.flags=flags;
		self.attributemask[0]=mask;
		self
	}

	pub fn attributes_xfrm(&mut self, xfrm: u64, mask: u64) -> &mut Self {
		self.attributes.xfrm=xfrm;
		self.attributemask[1]=mask;
		self
	}

	pub fn enclavehash(&mut self, hash: [u8; 32]) -> &mut Self {
		self.enclavehash=Some(hash);
		self
	}

	pub fn enclavehash_from_stream<R: io::Read>(&mut self, stream: &mut R) -> Result<&mut Self,io::Error> {
		let mut hasher=<Sha256 as Sha256Digest>::new();
		try!(io::copy(stream,&mut hasher));
		let mut hash=[0u8; 32];
		(&mut hash[..]).write_all(&hasher.finish()).unwrap();
		Ok(self.enclavehash(hash))
	}
}
