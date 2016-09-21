/*
 * Constants and structures related to the Intel SGX ISA extension.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * Licensed under the Apache License, Version 2.0
 * <COPYING-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT
 * license <COPYING-MIT or http://opensource.org/licenses/MIT>, at your
 * option. All files in the project carrying such notice may not be copied,
 * modified, or distributed except according to those terms.
 */

use core::mem::transmute;
use core::ptr;

use super::*;

macro_rules! impl_default_clone {
	($($t:ty, $size:expr;)*) => {$(
		impl Default for $t {
			fn default() -> $t {
				unsafe{transmute([0u8;$size])}
			}
		}
		impl Clone for $t {
			fn clone(&self) -> $t {
				unsafe{ptr::read(self)}
			}
		}
	)*}
}

impl_default_clone!{
	Secs, 4096;
	Tcs, 4096;
	Secinfo, 64;
	Pcmd, 128;
	Sigstruct, 1808;
	Einittoken, 304;
	Report, 432;
	Targetinfo, 512;
	Keyrequest, 512;
}

impl ::core::fmt::Debug for Secs {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Secs {
			size: ref __self_0_0,
			baseaddr: ref __self_0_1,
			ssaframesize: ref __self_0_2,
			miscselect: ref __self_0_3,
			attributes: ref __self_0_5,
			mrenclave: ref __self_0_6,
			mrsigner: ref __self_0_8,
			isvprodid: ref __self_0_10,
			isvsvn: ref __self_0_11, .. } => {
				let mut builder = __arg_0.debug_struct("Secs");
				let _ = builder.field("size", &&(*__self_0_0));
				let _ = builder.field("baseaddr", &&(*__self_0_1));
				let _ = builder.field("ssaframesize", &&(*__self_0_2));
				let _ = builder.field("miscselect", &&(*__self_0_3));
				let _ = builder.field("attributes", &&(*__self_0_5));
				let _ = builder.field("mrenclave", &&(*__self_0_6));
				let _ = builder.field("mrsigner", &&(*__self_0_8));
				let _ = builder.field("isvprodid", &&(*__self_0_10));
				let _ = builder.field("isvsvn", &&(*__self_0_11));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Tcs {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Tcs {
			flags: ref __self_0_1,
			ossa: ref __self_0_2,
			cssa: ref __self_0_3,
			nssa: ref __self_0_4,
			oentry: ref __self_0_5,
			ofsbasgx: ref __self_0_7,
			ogsbasgx: ref __self_0_8,
			fslimit: ref __self_0_9,
			gslimit: ref __self_0_10, .. } => {
				let mut builder = __arg_0.debug_struct("Tcs");
				let _ = builder.field("flags", &&(*__self_0_1));
				let _ = builder.field("ossa", &&(*__self_0_2));
				let _ = builder.field("cssa", &&(*__self_0_3));
				let _ = builder.field("nssa", &&(*__self_0_4));
				let _ = builder.field("oentry", &&(*__self_0_5));
				let _ = builder.field("ofsbasgx", &&(*__self_0_7));
				let _ = builder.field("ogsbasgx", &&(*__self_0_8));
				let _ = builder.field("fslimit", &&(*__self_0_9));
				let _ = builder.field("gslimit", &&(*__self_0_10));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Secinfo {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Secinfo { flags: ref __self_0_0, .. } => {
				let mut builder = __arg_0.debug_struct("Secinfo");
				let _ = builder.field("flags", &&(*__self_0_0));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Pcmd {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Pcmd {
			secinfo: ref __self_0_0,
			enclaveid: ref __self_0_1,
			mac: ref __self_0_3, .. } => {
				let mut builder = __arg_0.debug_struct("Pcmd");
				let _ = builder.field("secinfo", &&(*__self_0_0));
				let _ = builder.field("enclaveid", &&(*__self_0_1));
				let _ = builder.field("mac", &&(*__self_0_3));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Sigstruct {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Sigstruct {
			header: ref __self_0_0,
			vendor: ref __self_0_1,
			date: ref __self_0_2,
			header2: ref __self_0_3,
			swdefined: ref __self_0_4,
			modulus: ref __self_0_6,
			exponent: ref __self_0_7,
			signature: ref __self_0_8,
			miscselect: ref __self_0_9,
			miscmask: ref __self_0_10,
			attributes: ref __self_0_12,
			attributemask: ref __self_0_13,
			enclavehash: ref __self_0_14,
			isvprodid: ref __self_0_16,
			isvsvn: ref __self_0_17,
			q1: ref __self_0_19,
			q2: ref __self_0_20, .. } => {
				let mut builder = __arg_0.debug_struct("Sigstruct");
				let _ = builder.field("header", &&(*__self_0_0));
				let _ = builder.field("vendor", &&(*__self_0_1));
				let _ = builder.field("date", &&(*__self_0_2));
				let _ = builder.field("header2", &&(*__self_0_3));
				let _ = builder.field("swdefined", &&(*__self_0_4));
				let _ = builder.field("modulus", &"(384 bytes)");
				let _ = builder.field("exponent", &&(*__self_0_7));
				let _ = builder.field("signature", &"(384 bytes)");
				let _ = builder.field("miscselect", &&(*__self_0_9));
				let _ = builder.field("miscmask", &&(*__self_0_10));
				let _ = builder.field("attributes", &&(*__self_0_12));
				let _ = builder.field("attributemask", &&(*__self_0_13));
				let _ = builder.field("enclavehash", &&(*__self_0_14));
				let _ = builder.field("isvprodid", &&(*__self_0_16));
				let _ = builder.field("isvsvn", &&(*__self_0_17));
				let _ = builder.field("q1", &"(384 bytes)");
				let _ = builder.field("q2", &"(384 bytes)");
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Einittoken {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Einittoken {
			valid: ref __self_0_0,
			attributes: ref __self_0_2,
			mrenclave: ref __self_0_3,
			mrsigner: ref __self_0_5,
			cpusvnle: ref __self_0_7,
			isvprodidle: ref __self_0_8,
			isvsvnle: ref __self_0_9,
			maskedmiscselectle: ref __self_0_11,
			maskedattributesle: ref __self_0_12,
			keyid: ref __self_0_13,
			mac: ref __self_0_14, .. } => {
				let mut builder = __arg_0.debug_struct("Einittoken");
				let _ = builder.field("valid", &&(*__self_0_0));
				let _ = builder.field("attributes", &&(*__self_0_2));
				let _ = builder.field("mrenclave", &&(*__self_0_3));
				let _ = builder.field("mrsigner", &&(*__self_0_5));
				let _ = builder.field("cpusvnle", &&(*__self_0_7));
				let _ = builder.field("isvprodidle", &&(*__self_0_8));
				let _ = builder.field("isvsvnle", &&(*__self_0_9));
				let _ = builder.field("maskedmiscselectle", &&(*__self_0_11));
				let _ = builder.field("maskedattributesle", &&(*__self_0_12));
				let _ = builder.field("keyid", &&(*__self_0_13));
				let _ = builder.field("mac", &&(*__self_0_14));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Report {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Report {
			cpusvn: ref __self_0_0,
			miscselect: ref __self_0_1,
			attributes: ref __self_0_3,
			mrenclave: ref __self_0_4,
			mrsigner: ref __self_0_6,
			isvprodid: ref __self_0_8,
			isvsvn: ref __self_0_9,
			reportdata: ref __self_0_11,
			keyid: ref __self_0_12,
			mac: ref __self_0_13, .. } => {
				let mut builder = __arg_0.debug_struct("Report");
				let _ = builder.field("cpusvn", &&(*__self_0_0));
				let _ = builder.field("miscselect", &&(*__self_0_1));
				let _ = builder.field("attributes", &&(*__self_0_3));
				let _ = builder.field("mrenclave", &&(*__self_0_4));
				let _ = builder.field("mrsigner", &&(*__self_0_6));
				let _ = builder.field("isvprodid", &&(*__self_0_8));
				let _ = builder.field("isvsvn", &&(*__self_0_9));
				let _ = builder.field("reportdata", &"(64 bytes)");
				let _ = builder.field("keyid", &"(32 bytes)");
				let _ = builder.field("mac", &&(*__self_0_13));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Targetinfo {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Targetinfo {
			measurement: ref __self_0_0,
			attributes: ref __self_0_1,
			miscselect: ref __self_0_3, .. } => {
				let mut builder = __arg_0.debug_struct("Targetinfo");
				let _ = builder.field("measurement", &&(*__self_0_0));
				let _ = builder.field("attributes", &&(*__self_0_1));
				let _ = builder.field("miscselect", &&(*__self_0_3));
				builder.finish()
			}
		}
	}
}

impl ::core::fmt::Debug for Keyrequest {
	fn fmt(&self, __arg_0: &mut ::core::fmt::Formatter)
	 -> ::core::fmt::Result {
		match *self {
			Keyrequest {
			keyname: ref __self_0_0,
			keypolicy: ref __self_0_1,
			isvsvn: ref __self_0_2,
			cpusvn: ref __self_0_4,
			attributemask: ref __self_0_5,
			keyid: ref __self_0_6,
			miscmask: ref __self_0_7, .. } => {
				let mut builder = __arg_0.debug_struct("Keyrequest");
				let _ = builder.field("keyname", &&(*__self_0_0));
				let _ = builder.field("keypolicy", &&(*__self_0_1));
				let _ = builder.field("isvsvn", &&(*__self_0_2));
				let _ = builder.field("cpusvn", &&(*__self_0_4));
				let _ = builder.field("attributemask", &&(*__self_0_5));
				let _ = builder.field("keyid", &&(*__self_0_6));
				let _ = builder.field("miscmask", &&(*__self_0_7));
				builder.finish()
			}
		}
	}
}
