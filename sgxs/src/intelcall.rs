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

use std::io::Write;

use abi::{Sigstruct,Einittoken,Attributes,Enclu};
use sgxs::SgxsRead;
use loader::{Load,Map,Tcs,Error};
use loader::Error::*;
use crypto::{Sha256Digest,Sha256};

bitflags!{
	flags CpuidFlags: u64 {
		const ALWAYS_SET = 0x00000001,
		const FPU        = 0x00000002,
		const CMOV       = 0x00000004,
		const MMX        = 0x00000008,
		const FXSR       = 0x00000010,
		const SSE        = 0x00000020,
		const SSE2       = 0x00000040,
		const SSE3       = 0x00000080,
		const SSSE3      = 0x00000100,
		const SSE4_1     = 0x00000200,
		const SSE4_2     = 0x00000400,
		const POPCNT     = 0x00000800,
		const MOVBE      = 0x00001000,
		const PCLMULQDQ  = 0x00002000,
		const AES        = 0x00004000,
		const F16C       = 0x00008000,
		const AVX        = 0x00010000,
		const RDRND      = 0x00020000,
		const FMA3       = 0x00040000,
		const BMI1_BMI2  = 0x00080000,
		const LZCNT      = 0x00100000,
		const HLE        = 0x00200000,
		const RTM        = 0x00400000,
		const AVX2       = 0x00800000,
		const RESERVED1  = 0x01000000,
		const PREFETCHW  = 0x02000000,
		const RDSEED     = 0x04000000,
		const ADX        = 0x08000000,
		const ATOM       = 0x10000000,
	}
}

#[allow(dead_code)]
#[repr(packed)]
struct GetTokenCall {
	unused: u64,
	mrenclave: *const [u8;32],
	mrsigner: *const [u8;32],
	attributes: *const Attributes,
	einittoken: *mut Einittoken,
}

pub fn get_einittoken<'dev,'r,D: ?Sized,R>(device: &'dev D, enclave_sig: &Sigstruct, enclave_token: &mut Einittoken, requested_attributes: &Attributes, le: &'r mut R, le_sig: &Sigstruct)
	-> Result<(),Error<D::Error>> where D: Load<'dev>, R: SgxsRead + 'r {
	let mut le_mapped=match device.load(le,le_sig,None) {
		Err(err) => return Err(LaunchEnclaveLoad(err)),
		Ok(m) => m,
	};

	if le_mapped.tcss().len()!=1 {
		return Err(LaunchEnclaveTcsCount);
	}

	let flags=get_cpuid_flags().bits;
	let (rdi,rsi)=enclu_eenter(&mut le_mapped.tcss()[0],0xffffffff,&flags as *const _ as u64);
	if (rdi,rsi)!=(0xffffffffffffffff,0) {
		return Err(LaunchEnclaveInit(rdi,rsi));
	}

	let mut sha=<Sha256 as Sha256Digest>::new();
	sha.write(&enclave_sig.modulus).unwrap();
	let mrsigner=sha.finish();

	let callbuf=GetTokenCall{
		unused:0,
		mrenclave: &enclave_sig.enclavehash,
		mrsigner: mrsigner.as_ptr() as *const _,
		attributes: requested_attributes,
		einittoken: enclave_token,
	};

	let (rdi,rsi)=enclu_eenter(&mut le_mapped.tcss()[0],0,&callbuf as *const _ as u64);
	if (rdi,rsi)!=(0xffffffffffffffff,0) {
		return Err(LaunchEnclaveGetToken(rdi,rsi));
	}

	Ok(())
}

fn enclu_eenter(tcs: &mut Tcs, mut rdi: u64, mut rsi: u64) -> (u64,u64) {
	let eax: u32;
	unsafe{asm!("
		lea aep(%rip),%rcx
aep:
		enclu
"		: "={eax}"(eax), "={rdi}"(rdi), "={rsi}"(rsi)
		: "{eax}"(Enclu::EEnter), "{rbx}"(u64::from(tcs.address())), "{rdi}"(rdi), "{rsi}"(rsi)
		: "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
		: "volatile"
	)};

	if eax!=(Enclu::EExit as u32) {
		panic!("Invalid return value in EAX! eax={}",eax);
	}
	(rdi,rsi)
}

pub fn get_cpuid_flags() -> CpuidFlags {
	let (cpuid1_eax,_,cpuid1_ecx,cpuid1_edx)=cpuid(1);
	let (_,cpuid7_ebx,_,_)=cpuid(7);
	let (_,_,cpuid80000001_ecx,_)=cpuid(0x80000001);
	let mut ret=ALWAYS_SET;

	let osxsave=cpuid1_ecx[27];
	let fxsr=cpuid1_edx[24];
	let model=((cpuid1_eax.0 >> 12)&0xf0) | ((cpuid1_eax.0 >> 4)&0xf);

	if cpuid1_edx[0]                             { ret.insert(FPU      ); }
	if cpuid1_edx[15]                            { ret.insert(CMOV     ); }
	if cpuid1_edx[23]                            { ret.insert(MMX      ); }
	if fxsr                                      { ret.insert(FXSR     ); }
	if cpuid1_edx[25] && fxsr                    { ret.insert(SSE      ); }
	if cpuid1_edx[26] && fxsr                    { ret.insert(SSE2     ); }
	if cpuid1_ecx[0] && fxsr                     { ret.insert(SSE3     ); }
	if cpuid1_ecx[9] && fxsr                     { ret.insert(SSSE3    ); }
	if cpuid1_ecx[19] && fxsr                    { ret.insert(SSE4_1   ); }
	if cpuid1_ecx[20] && fxsr                    { ret.insert(SSE4_2   ); }
	if cpuid1_ecx[23] && fxsr                    { ret.insert(POPCNT   ); }
	if cpuid1_ecx[22] && fxsr                    { ret.insert(MOVBE    ); }
	if cpuid1_ecx[1] && fxsr                     { ret.insert(PCLMULQDQ); }
	if cpuid1_ecx[25] && fxsr                    { ret.insert(AES      ); }
	if cpuid1_ecx[29] && osxsave                 { ret.insert(F16C     ); }
	if cpuid1_ecx[28] && osxsave                 { ret.insert(AVX      ); }
	if cpuid1_ecx[30]                            { ret.insert(RDRND    ); }
	if cpuid1_ecx[12] && osxsave                 { ret.insert(FMA3     ); }
	if cpuid7_ebx[3] && cpuid7_ebx[8]            { ret.insert(BMI1_BMI2); }
	if cpuid80000001_ecx[5]                      { ret.insert(LZCNT    ); }
	if cpuid7_ebx[4]                             { ret.insert(HLE      ); }
	if cpuid7_ebx[11]                            { ret.insert(RTM      ); }
	if cpuid7_ebx[5] && osxsave                  { ret.insert(AVX2     ); }
	if cpuid80000001_ecx[8]                      { ret.insert(PREFETCHW); }
	if cpuid7_ebx[18]                            { ret.insert(RDSEED   ); }
	if cpuid7_ebx[19]                            { ret.insert(ADX      ); }
	if model==0x1c || model==0x26 || model==0x27 { ret.insert(ATOM     ); }

	ret
}

#[repr(packed)]
struct Bitfield<T>(T);

impl ::std::ops::Index<usize> for Bitfield<u32> {
	type Output = bool;
	fn index(&self, index: usize) -> &bool {
		static FALSE: bool=false;
		static TRUE: bool=true;

		if (self.0&(1<<index)) == 0 {
			return &FALSE;
		} else {
			return &TRUE;
		}
	}
}

fn cpuid(eax: u32)->(Bitfield<u32>,Bitfield<u32>,Bitfield<u32>,Bitfield<u32>) {
	let mut out=(Bitfield(0),Bitfield(0),Bitfield(0),Bitfield(0));
	unsafe{asm!("cpuid"
		: "={eax}"(out.0 .0), "={ebx}"(out.1 .0), "={ecx}"(out.2 .0), "={edx}"(out.3 .0)
		: "{eax}"(eax), "{ecx}"(0)
	)};
	out
}
