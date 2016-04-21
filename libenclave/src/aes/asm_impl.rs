/*
 * The Rust secure enclave runtime and library.
 *
 * Copyright(c) 2012, Intel Corp.
 * Copyright(c) 2009, Red Hat Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU Affero General Public License, as described below:
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

#![allow(improper_ctypes)]

use rustc_alloc::boxed::Box;
use core;

// This magic number is (Nb_max * (Nr_max + 1))
// where Nb_max is the maximum block size in 32-bit words,
//       Nr_max is the maximum number of rounds, which is Nb_max + 6
pub const AES_MAX_EXP_KEY_SIZE: usize = 8*15;

pub const AES_BLOCK_SIZE: usize = 16;

#[repr(C)]
pub struct KeySchedule {
	_nb: u32,
	pub nr: u32,
	_freebl_cipher_func: *const (),
	_iv: [u8;AES_BLOCK_SIZE*2],
	pub ks: [u32;AES_MAX_EXP_KEY_SIZE],
}

impl KeySchedule {
	fn new() -> KeySchedule {
		KeySchedule{
			_nb:0,
			nr:0,
			_freebl_cipher_func:core::ptr::null(),
			_iv:[0;AES_BLOCK_SIZE*2],
			ks:[0u32;AES_MAX_EXP_KEY_SIZE],
		}
	}
}

#[repr(C)]
pub struct GcmContext {
	pub htbl: [u8;16*AES_BLOCK_SIZE],
	pub x0: [u8;AES_BLOCK_SIZE],
	pub t: [u8;AES_BLOCK_SIZE],
	pub ctr: [u8;AES_BLOCK_SIZE],
	pub ks: Box<KeySchedule>,
}

impl GcmContext {
	pub fn new() -> GcmContext {
		GcmContext{
			htbl:[0;16*AES_BLOCK_SIZE],
			x0:[0;AES_BLOCK_SIZE],
			t:[0;AES_BLOCK_SIZE],
			ctr:[0;AES_BLOCK_SIZE],
			ks:Box::new(KeySchedule::new()),
		}
	}
}

// Definitions for the assembly functions
extern "C" {
	/* Prepares the constants used in the aggregated reduction method */
	pub fn intel_aes_gcmINIT(htbl: *mut [u8;16*AES_BLOCK_SIZE], ks: *const [u32;AES_MAX_EXP_KEY_SIZE], nr: u32);

	/* Produces the final GHASH value */
	pub fn intel_aes_gcmTAG(htbl: *const [u8;16*AES_BLOCK_SIZE],
							t: *const [u8;AES_BLOCK_SIZE],
							m_len: usize,
							a_len: usize,
							x0: *const [u8;AES_BLOCK_SIZE],
							tag: *mut [u8;AES_BLOCK_SIZE]);

	/* Hashes the Additional Authenticated Data, should be used before enc/dec.
	   Operates on whole blocks only. Partial blocks should be padded externally. */
	pub fn intel_aes_gcmAAD(htbl: *const [u8;16*AES_BLOCK_SIZE],
							aad: *const u8,
							len: usize,
							t: *mut [u8;AES_BLOCK_SIZE]);

	/* Encrypts and hashes the Plaintext.
	   Operates on any length of data, however partial block should only be encrypted
	   at the last call, otherwise the result will be incorrect. */
	pub fn intel_aes_gcmENC(pt: *const u8,
							ct: *mut u8,
							gctx: *mut GcmContext,
							len: usize);

	/* Similar to ENC, but decrypts the Ciphertext. */
	pub fn intel_aes_gcmDEC(ct: *const u8,
							pt: *mut u8,
							gctx: *mut GcmContext,
							len: usize);

	pub fn intel_aes_encrypt_init_128(key: *const [u8;128/8], ks: *mut [u32;AES_MAX_EXP_KEY_SIZE]);
	pub fn intel_aes_encrypt_init_192(key: *const [u8;192/8], ks: *mut [u32;AES_MAX_EXP_KEY_SIZE]);
	pub fn intel_aes_encrypt_init_256(key: *const [u8;256/8], ks: *mut [u32;AES_MAX_EXP_KEY_SIZE]);
}
