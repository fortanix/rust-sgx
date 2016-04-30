/*
 * The Rust secure enclave runtime and library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

use core;

mod asm_impl;
use self::asm_impl::*;

pub fn cmac_128(key: &[u8;16], data: &[u8]) -> [u8;16]  {
	let mut ks=[0u32;AES_MAX_EXP_KEY_SIZE];
	unsafe{intel_aes_encrypt_init_128(key,&mut ks)};
	let first_len=if data.len()==0 {
		0
	} else {
		(data.len()-1)&!(AES_BLOCK_SIZE-1)
	};
	let (data,last)=data.split_at(first_len);
	let mut last_block=[0u8;AES_BLOCK_SIZE];
	let k1_or_k2=if last.len()==16 { 0u8 /*k1*/ } else { 1u8 /*k2*/ };
	for (dst,src) in last_block.iter_mut().zip(last.iter().chain(&[0x80][..])) {
		*dst=*src;
	}

	let _tmp1: u64;
	let _tmp2: u64;
	let mut out=[0u8;16];
	unsafe{asm!("
// Load key schedule
		movdqu  0x00($0), %xmm2
		movdqu  0x10($0), %xmm3
		movdqu  0x20($0), %xmm4
		movdqu  0x30($0), %xmm5
		movdqu  0x40($0), %xmm6
		movdqu  0x50($0), %xmm7
		movdqu  0x60($0), %xmm8
		movdqu  0x70($0), %xmm9
		movdqu  0x80($0), %xmm10
		movdqu  0x90($0), %xmm11
		movdqu  0xa0($0), %xmm12

// Set initial (zero) block
		mov     $$-16, %rax
		pxor    %xmm1, %xmm1

0: /* aes */
		pxor       %xmm2,  %xmm1
		aesenc     %xmm3,  %xmm1
		aesenc     %xmm4,  %xmm1
		aesenc     %xmm5,  %xmm1
		aesenc     %xmm6,  %xmm1
		aesenc     %xmm7,  %xmm1
		aesenc     %xmm8,  %xmm1
		aesenc     %xmm9,  %xmm1
		aesenc     %xmm10, %xmm1
		aesenc     %xmm11, %xmm1
		aesenclast %xmm12, %xmm1

		addq    $$16, %rax
		jnz 1f /* not_initial_block */
/* initial_block */
// Store encrypted zero-block (k0)
		movdqa	%xmm1, %xmm13
		pxor    %xmm1, %xmm1
1: /* not_initial_block */
		cmpq    $7, %rax
		je 2f /* last_block */
		ja 5f /* after_last_block */
		movdqu  ($1, %rax), %xmm0
		pxor       %xmm0,  %xmm1
		jmp 0b /* aes */

2: /* last_block */
		movq %xmm13,$0
		bswap $0
		pextrq $$1,%xmm13,$1
		bswap $1
// Calculate k1
		shl $$1,$1
		rcl $$1,$0
		jnc 3f /* skip_xor1 */
		xor $$0x87,$1
3: /* skip_xor1 */
		test $6, $6
		jz 4f /* skip_k2 */
// Calculate k2
		shl $$1,$1
		rcl $$1,$0
		jnc 4f /* skip_xor2 */
		xor $$0x87,$1
4: /* skip_xor2, skip_k2 */
		bswap $0
		movq $0,%xmm13
		bswap $1
		pinsrq $$1,$1,%xmm13
// Load last block
		movdqu  ($5), %xmm0
		pxor       %xmm13, %xmm1
		pxor       %xmm0,  %xmm1
		jmp 0b /* aes */

5: /* after_last_block */
		movdqu  %xmm1, ($4)"
	: /*0*/"=r"(_tmp1),/*1*/"=r"(_tmp2)
	: /*2*/"0"(ks.as_ptr()),/*3*/"1"(data.as_ptr()),/*4*/"r"(out.as_mut_ptr()),
	  /*5*/"r"(last_block.as_ptr()),/*6*/"r"(k1_or_k2),/*7*/"r"(first_len)
	: "rax","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8",
	  "xmm9","xmm10","xmm11","xmm12","xmm13","memory"
	)};
	out
}

#[derive(PartialEq,Eq)]
enum State {
	New,
	Aad,
	AadFinal,
	Encrypting,
	Decrypting,
	Done,
}

pub struct AesGcm {
	gctx: GcmContext,
	a_len: usize,
	m_len: usize,
	state: State,
}

impl Clone for AesGcm {
    fn clone(&self) -> Self {
		if self.state!=State::New { panic!("Can't clone in this state") };
		AesGcm{gctx:self.gctx.clone(),a_len:0,m_len:0,state:State::New}
	}
}

impl AesGcm {
	pub fn new(k: &[u8], iv: &[u8]) -> AesGcm {
		let mut gctx=GcmContext::new();
		match k.len() {
			16 => {unsafe{intel_aes_encrypt_init_128(k.as_ptr() as *const _,&mut gctx.ks.ks)};gctx.ks.nr=10}
			24 => {unsafe{intel_aes_encrypt_init_192(k.as_ptr() as *const _,&mut gctx.ks.ks)};gctx.ks.nr=12}
			32 => {unsafe{intel_aes_encrypt_init_256(k.as_ptr() as *const _,&mut gctx.ks.ks)};gctx.ks.nr=14}
			_ => panic!("Invalid AES keysize!")
		};
		unsafe{intel_aes_gcmINIT(&mut gctx.htbl,&gctx.ks.ks,gctx.ks.nr)};
		if iv.len()==12 {
			unsafe{core::ptr::copy(iv.as_ptr(),gctx.ctr.as_mut_ptr(),12)};
			gctx.ctr[15]=1;
		} else {
			panic!("Only 96-bit IV supported!")
		}
		let mut out=[0u8;AES_BLOCK_SIZE];
		unsafe{intel_aes_gcmENC([0u8;AES_BLOCK_SIZE].as_ptr(),out.as_mut_ptr(),&mut gctx,AES_BLOCK_SIZE)};
		gctx.x0=out;
		gctx.t=[0u8;AES_BLOCK_SIZE];
		AesGcm{gctx:gctx,a_len:0,m_len:0,state:State::New}
	}

	pub fn aad(&mut self, mut data: &[u8]) {
		match self.state { State::New | State::Aad => {}, _ => panic!("Can't add AAD in this state") };
		self.a_len+=data.len();

		let partial=data.len()%AES_BLOCK_SIZE;
		let mut data2=[0u8;AES_BLOCK_SIZE];
		if partial!=0 {
			let (a,b)=data.split_at(data.len()-partial);
			data=a;
			unsafe{core::ptr::copy(b.as_ptr(),data2.as_mut_ptr(),partial)};
			self.state=State::AadFinal;
		} else {
			self.state=State::Aad;
		}
		unsafe{
			intel_aes_gcmAAD(&self.gctx.htbl,data.as_ptr(),data.len(),&mut self.gctx.t);
			if partial!=0 {
				intel_aes_gcmAAD(&self.gctx.htbl,data2.as_ptr(),data2.len(),&mut self.gctx.t);
			}
		}
	}

	pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
		assert_eq!(plaintext.len(),ciphertext.len());
		match self.state { State::Decrypting | State::Done => panic!("Can't encrypt in this state"), _ => {} };
		if plaintext.len()%AES_BLOCK_SIZE == 0 {
			self.state=State::Encrypting;
		} else {
			self.state=State::Done;
		}

		self.m_len+=plaintext.len();
		unsafe{intel_aes_gcmENC(plaintext.as_ptr(),ciphertext.as_mut_ptr(),&mut self.gctx,plaintext.len())};
	}

	pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) {
		assert_eq!(plaintext.len(),ciphertext.len());
		match self.state { State::Encrypting | State::Done => panic!("Can't decrypt in this state"), _ => {} };
		if plaintext.len()%AES_BLOCK_SIZE == 0 {
			self.state=State::Decrypting;
		} else {
			self.state=State::Done;
		}

		self.m_len+=plaintext.len();
		unsafe{intel_aes_gcmDEC(ciphertext.as_ptr(),plaintext.as_mut_ptr(),&mut self.gctx,plaintext.len())};
	}

	pub fn tag(&self) -> [u8;16] {
		let mut tag=[0u8;AES_BLOCK_SIZE];
		unsafe{intel_aes_gcmTAG(&self.gctx.htbl,&self.gctx.t,self.m_len,self.a_len,&self.gctx.x0,&mut tag)};
		return tag;
	}
}

#[cfg(test)]
mod tests {
	use super::{cmac_128,AesGcm};
	use core::iter::repeat;
	use collections::Vec;

	fn hex_to_num(ascii: u8) -> u8 {
		match ascii {
			b'0' ... b'9' => ascii-b'0',
			b'A' ... b'F' => ascii-b'A'+10,
			b'a' ... b'f' => ascii-b'a'+10,
			_ => panic!("Not hex!")
		}
	}

	fn hex_to_bytes(raw_hex: &str) -> Vec<u8> {
		raw_hex.as_bytes().chunks(2).map(|b|(hex_to_num(b[0])<<4) + hex_to_num(b[1])).collect()
	}

	struct TestVector {
		key:  Vec<u8>,
		iv:  Vec<u8>,
		plain_text: Vec<u8>,
		cipher_text:  Vec<u8>,
		aad: Vec<u8>,
		tag:  Vec<u8>,
	}

	fn gcm_test_vectors() -> [TestVector; 5] {
		[
			TestVector {
				key: hex_to_bytes("00000000000000000000000000000000"),
				iv: hex_to_bytes("000000000000000000000000"),
				plain_text: hex_to_bytes(""),
				cipher_text: hex_to_bytes(""),
				aad: hex_to_bytes(""),
				tag: hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a")
			},
			TestVector {
				key: hex_to_bytes("00000000000000000000000000000000"),
				iv: hex_to_bytes("000000000000000000000000"),
				plain_text: hex_to_bytes("00000000000000000000000000000000"),
				cipher_text: hex_to_bytes("0388dace60b6a392f328c2b971b2fe78"),
				aad: hex_to_bytes(""),
				tag: hex_to_bytes("ab6e47d42cec13bdf53a67b21257bddf")
			},
			TestVector {
				key: hex_to_bytes("feffe9928665731c6d6a8f9467308308"),
				iv: hex_to_bytes("cafebabefacedbaddecaf888"),
				plain_text: hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
				cipher_text: hex_to_bytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"),
				aad: hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
				tag: hex_to_bytes("5bc94fbc3221a5db94fae95ae7121a47")
			},
			TestVector {
				key: hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c"),
				iv: hex_to_bytes("cafebabefacedbaddecaf888"),
				plain_text: hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
				cipher_text: hex_to_bytes("3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710"),
				aad: hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
				tag: hex_to_bytes("2519498e80f1478f37ba55bd6d27618c")
			},
			TestVector {
				key: hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
				iv: hex_to_bytes("cafebabefacedbaddecaf888"),
				plain_text: hex_to_bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
				cipher_text: hex_to_bytes("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"),
				aad: hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
				tag: hex_to_bytes("76fc6ece0f4e1768cddf8853bb2d551b")
			},
		]
	}

	fn cmac_test_vectors() -> [TestVector; 37] {
		[
			TestVector {
				key: hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
				plain_text: hex_to_bytes(""),
				tag: hex_to_bytes("bb1d6929e95937287fa37d129b756746"),
				iv: Vec::with_capacity(0),
				cipher_text: Vec::with_capacity(0),
				aad: Vec::with_capacity(0),
			},
			TestVector {
				key: hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
				plain_text: hex_to_bytes("6bc1bee22e409f96e93d7e117393172a"),
				tag: hex_to_bytes("070a16b46b4d4144f79bdd9dd04a287c"),
				iv: Vec::with_capacity(0),
				cipher_text: Vec::with_capacity(0),
				aad: Vec::with_capacity(0),
			},
			TestVector {
				key: hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
				plain_text: hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
				tag: hex_to_bytes("dfa66747de9ae63030ca32611497c827"),
				iv: Vec::with_capacity(0),
				cipher_text: Vec::with_capacity(0),
				aad: Vec::with_capacity(0),
			},
			TestVector {
				key: hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c"),
				plain_text: hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
				tag: hex_to_bytes("51f0bebf7e3b9d92fc49741779363cfe"),
				iv: Vec::with_capacity(0),
				cipher_text: Vec::with_capacity(0),
				aad: Vec::with_capacity(0),
			},
			TestVector{key:hex_to_bytes("5acc2951d3644f648fc73267895c8151"), plain_text:hex_to_bytes("8a"), tag:hex_to_bytes("8ca3202a393aaf356695c17a909a2023"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("d659299047f932ad129391258918ce52"), plain_text:hex_to_bytes("b46c"), tag:hex_to_bytes("1f1169ad1896a6734c604ee6fb4713f9"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("260829e2cbec93aa19b11d08a08dd8fa"), plain_text:hex_to_bytes("79cf56"), tag:hex_to_bytes("e76debc24beb76004bc649aae90f1a3e"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("c7235f4489eb97f594eb85a3dc95e0a6"), plain_text:hex_to_bytes("3c7368fb"), tag:hex_to_bytes("83b0b0b9d4dc0ee08a368b788d97d3db"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("98adf2c1ae8d14c7f3178135c5a9e74b"), plain_text:hex_to_bytes("0f50448532"), tag:hex_to_bytes("cc571b3d73a608c56756590c59fc941c"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("0a1c812701e438fff5c99a2e0ac28dcb"), plain_text:hex_to_bytes("63f2a1f8e8ba"), tag:hex_to_bytes("81891feefb770015eeb0479e4d7aa1cc"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("686826aa8bb22aaedde12e852702549c"), plain_text:hex_to_bytes("36063a41936875"), tag:hex_to_bytes("637a35dba9c5b998cdbec17d960c01ba"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("aeae7313625e74842e1ad81aa94a3173"), plain_text:hex_to_bytes("9bd1cf1455f1a1fe"), tag:hex_to_bytes("2210ca367a65fea5b5aed49072e51fcc"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("b9a104da123f6d82c9756144c9b83c67"), plain_text:hex_to_bytes("e63e3bf6b2785de2c7"), tag:hex_to_bytes("65c1b064d0c2553f58d6651489bfb51b"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("6a9535bb9bb2a5879ea6a1363e44adc3"), plain_text:hex_to_bytes("ecc21529048f0977304e"), tag:hex_to_bytes("46cfb8be17ffee08549f84b81b6ea0bc"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("d31eb8efde214a9a6bd92346467c8b82"), plain_text:hex_to_bytes("24565c728e953d73d1e2b3"), tag:hex_to_bytes("d71e021d0749c2e1098a721320ce14b5"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("9a06c2db615b1202463475713ec53b91"), plain_text:hex_to_bytes("5c40d7694cba83dcdef9f27b"), tag:hex_to_bytes("540f259e95178c10ea0a2ab59b8bd417"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("ae8075821f82fdf179f06325c7fc2467"), plain_text:hex_to_bytes("9df605c7d2ea03473a7cdc83d3"), tag:hex_to_bytes("dce24066a2395db4fea2c93abcf963d0"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("b5b17c457c0edd460807d5e5942a3287"), plain_text:hex_to_bytes("5e2bd863605800cfb183705ffe12"), tag:hex_to_bytes("eeafc0770d9b7b842f4c54b54376d87d"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("9f49903af819989506889c6fbcd477c1"), plain_text:hex_to_bytes("4372a702b6161b3c020a6078523c25"), tag:hex_to_bytes("57da254e39cc770ae12c5e0b8066668e"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("222c2cbcc3309189157fedc7a7086936"), plain_text:hex_to_bytes("4c9f074836948c6a6f2451c6aba68c5e"), tag:hex_to_bytes("ea038e3857fae7add29a8c8635b2a9f5"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("065049fd7d4356e9aa30d6bec36a6389"), plain_text:hex_to_bytes("8cf58fc3471c9c806051c208eb5da42277"), tag:hex_to_bytes("73f466a29bdc877e3d9e70c782dae6bb"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("b235d901227108a52d9e199a2fa3246d"), plain_text:hex_to_bytes("f18c65ea776ddee640c2d770b383fae226e6"), tag:hex_to_bytes("35574b059a8449774a9f76068ce722d0"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("ddc3085a0e5b3d9496553063fe37be0f"), plain_text:hex_to_bytes("6fa02b897afd43db981f891a964e0dd3a7e910"), tag:hex_to_bytes("788a8a78c0c7465ed4e353742d830289"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("010866a39c7f6b35975584ca8faaa4a4"), plain_text:hex_to_bytes("73da5e1e1763f0fd4272784fb245412a8af98ea7"), tag:hex_to_bytes("ea41dae0779af77ce5c70b5072b09db8"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("f642124f81b5239f30a056d32f09a7ec"), plain_text:hex_to_bytes("d642f3dd853aa78952106b8a7f349ffa2f3ed0176e"), tag:hex_to_bytes("b576327d22a32e849011238369d74587"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("e54972a31a37d7b68e200f55757b8f26"), plain_text:hex_to_bytes("88f8aef13fdd0cafbd0cfb7fbc1238d6c8d797f4bc8c"), tag:hex_to_bytes("4d80534d763f3275362fe2a7d4f4d8ad"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("9d9fe248489ef5a8fb4bb721c3e62b3f"), plain_text:hex_to_bytes("9290820e669d228d40fdb37c73ecb952b05e1d206de20b"), tag:hex_to_bytes("20bc4e2ac3888a83680d2e285641002c"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("537fd9eb4c8d972e07aca49edca78c3b"), plain_text:hex_to_bytes("5355cdac27da9e65473b3f548d2c3eb8e92f1dc0f2a81c01"), tag:hex_to_bytes("d342ddee5a95365ef9084f119b05e031"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("abeb891353e7eca082f83d05a368c399"), plain_text:hex_to_bytes("b03d47932fefc42f8a86e6f6de74f07f12583a2b532244eb94"), tag:hex_to_bytes("b3480fa14d25496e1a4c97818b11a486"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("4e65612078dff2372f627269915e1cff"), plain_text:hex_to_bytes("1163fa80546fe7b3da0df719b814c53533a585b6ad3c6aa557dd"), tag:hex_to_bytes("0453ee0dd228ec41dcffe6426bb61e12"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("b3b3545f59a2857762173c216be7ffd2"), plain_text:hex_to_bytes("a9c363237c7fd7f579a2fb7f6e3c7771b33e66ed0465a46aae1024"), tag:hex_to_bytes("98112aa3036ed6c69af0c2031e9e7c45"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("d1962d899c81cddcf1200d777459bd59"), plain_text:hex_to_bytes("ec7966c65e7e13e4c6083950d9c426e9ccacaf98623d7cd79b3106fb"), tag:hex_to_bytes("cd258ae726671b6265363aac91a365e3"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("258fe26621083194d84330a1f3dbc415"), plain_text:hex_to_bytes("d8bdacd885d73a17ddf4d9de1f43398500710d9f565565ab91945a792b"), tag:hex_to_bytes("c8e232e1221b231d8fd059df9af62312"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("2735631c78a507334dd5f16605abe014"), plain_text:hex_to_bytes("631b721ed9d44a610bba32f23b3c2f6117091fd13814469ef55e83b80f9c"), tag:hex_to_bytes("4e9dd5295518313a0c302dff019b55a8"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("529123009f8a3b96efe7565eed7c2829"), plain_text:hex_to_bytes("cc1f8ff0e93ec8f949f6785df890b25964ecd511b5a4af4ad4b0deba3516ef"), tag:hex_to_bytes("e89f8401a25904cea71b9e0a179a4f03"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("ad6acc48b3d71a2151ff598fc4b9cea2"), plain_text:hex_to_bytes("4f5290e1c2392a9a2d304e1718adc51a406419fd72c50c081bd4d86fcc2727c1"), tag:hex_to_bytes("3cc498b05aa41100aef1aa6f54703445"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
			TestVector{key:hex_to_bytes("ba0efc383ab24c5e15264ba313de2f0c"), plain_text:hex_to_bytes("87af4789c661cae8866caa0f2e3374de2ff49e763dde89b07582bb98fe3782168e"), tag:hex_to_bytes("26666396851beb7efa1845df630b609f"), iv: Vec::with_capacity(0), cipher_text: Vec::with_capacity(0), aad: Vec::with_capacity(0),},
		]
	}

	#[test]
	fn aes_cmac_test() {
		for item in cmac_test_vectors().iter() {
			assert_eq!(item.key.len(),16);
			let mut key=[0u8;16];
			for (s,d) in item.key.iter().zip(key.iter_mut()) { *d=*s }
			assert_eq!(&cmac_128(&key,&item.plain_text)[..], &item.tag[..]);
		}
	}

	#[test]
	fn aes_gcm_test() {
		for item in gcm_test_vectors().iter() {
			let mut cipher = AesGcm::new(&item.key, &item.iv);
			cipher.aad(&item.aad);
			let mut out: Vec<u8> = repeat(0).take(item.plain_text.len()).collect();
			cipher.encrypt(&item.plain_text, &mut out[..]);
			let out_tag=cipher.tag();
			assert_eq!(out, item.cipher_text);
			assert_eq!(&out_tag[..], &item.tag[..]);
		}
	}

	#[test]
	fn aes_gcm_decrypt_test() {
		for item in gcm_test_vectors().iter() {
			let mut decipher = AesGcm::new(&item.key, &item.iv);
			decipher.aad(&item.aad);
			let mut out: Vec<u8> = repeat(0).take(item.plain_text.len()).collect();
			decipher.decrypt(&item.cipher_text, &mut out[..]);
			let out_tag=decipher.tag();
			assert_eq!(out, item.plain_text);
			assert_eq!(&out_tag[..], &item.tag[..]);
		}
	}
}
