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

use sgx_isa::Enclu;
pub use sgx_isa::{Keyname,Keypolicy,Keyrequest,Report,Targetinfo,ErrorCode};
use rustc_alloc::{heap,oom};
use core::{ptr,mem};
use aes;

pub fn egetkey(req: &Keyrequest) -> Result<[u8;16],ErrorCode> {
	let req_p;
	let out_p;
	let out;
	let error;
	unsafe {
		// Keyrequest alignment: EGETKEY says 128 bytes, but KEYREQUEST says 512?
		req_p=heap::allocate(mem::size_of::<Keyrequest>(),512) as *mut Keyrequest;
		out_p=heap::allocate(16,16) as *mut [u8;16];

		if req_p==ptr::null_mut() || out_p==ptr::null_mut() { oom() }
		ptr::copy(req,req_p,1);

		asm!("enclu":"={eax}"(error):"{eax}"(Enclu::EGetkey),"{rbx}"(req_p),"{rcx}"(out_p));

		out=*out_p;
		heap::deallocate(req_p as *mut _,mem::size_of::<Keyrequest>(),512);
		heap::deallocate(out_p as *mut _,16,16);
	}
	match ErrorCode::from_repr(error) {
		Some(ErrorCode::Success) => Ok(out),
		Some(err) => Err(err),
		None => panic!("EGETKEY returned invalid error code"),
	}
}

pub fn ereport(tinfo: &Targetinfo, rdata: &[u8; 64]) -> Report {
	ereport_internal(Some(tinfo),Some(rdata))
}

/// Useful to get information about the current enclave and how it was loaded
pub fn ereport_self() -> Report {
	ereport_internal(None,None)
}

/// Checks whether the report was generated on the same processor with this
/// enclave specified in the target.
pub fn verify_report(report: &Report) -> bool {
	let req=Keyrequest{
		keyname: Keyname::Report as u16,
		keyid: report.keyid,
		..Default::default()
	};
	let key=egetkey(&req).expect("Couldn't get report key");
	let mac_data=unsafe{::core::slice::from_raw_parts(report as *const _ as *const u8,384)};
	aes::cmac_128(&key,mac_data)==report.mac
}

fn ereport_internal(tinfo: Option<&Targetinfo>, rdata: Option<&[u8; 64]>) -> Report {
	let tinfo_p;
	let rdata_p;
	let report_p;
	let report;
	unsafe {
		// Targetinfo alignment: EREPORT says 128 bytes, but TARGETINFO says 512?
		tinfo_p=heap::allocate(mem::size_of::<Targetinfo>(),512) as *mut Targetinfo;
		// EREPORT says 128-byte alignment?
		rdata_p=heap::allocate(64,128) as *mut [u8;64];
		report_p=heap::allocate(mem::size_of::<Report>(),512) as *mut Report;

		if tinfo_p==ptr::null_mut() || rdata_p==ptr::null_mut() || report_p==ptr::null_mut() { oom() }

		match tinfo {
			Some(tinfo) => ptr::copy(tinfo,tinfo_p,1),
			None => ptr::write_bytes(tinfo_p,0,1),
		};
		match rdata {
			Some(rdata) => ptr::copy(rdata,rdata_p,1),
			None => ptr::write_bytes(rdata_p,0,1),
		};

		asm!("enclu"::"{eax}"(Enclu::EReport),"{rbx}"(tinfo_p),"{rcx}"(rdata_p),"{rdx}"(report_p));

		report=ptr::read(report_p);
		heap::deallocate(tinfo_p as *mut _,mem::size_of::<Targetinfo>(),512);
		heap::deallocate(rdata_p as *mut _,64,128);
		heap::deallocate(report_p as *mut _,mem::size_of::<Report>(),512);
	}
	report
}
