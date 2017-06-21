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

//! Constants and structures related to the Intel SGX ISA extension.
//!
//! These are taken directly from the [Intel Software Developer's Manual][isdm],
//! volume 3, chapters 37–43. Rust conversions traits were added where
//! convenient.
//!
//! [isdm]: https://www-ssl.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html


#![no_std]
#![cfg_attr(feature="try_from",feature(try_from))]

#[macro_use]
extern crate bitflags;

macro_rules! enum_def {
	(
		#[derive($($derive:meta),*)]
		#[repr($repr:ident)]
		pub enum $name:ident {
			$($key:ident = $val:expr,)*
		}
	) => (
		#[derive($($derive),*)]
		#[repr($repr)]
		pub enum $name {
			$($key = $val,)*
		}

		#[cfg(feature="try_from")]
		impl ::core::convert::TryFrom<$repr> for $name {
			type Err=::core::num::TryFromIntError;
			fn try_from(v: $repr) -> Result<Self, Self::Err> {
				match v {
					$($val => Ok($name::$key),)*
					_ => Err(u8::try_from(256u16).unwrap_err()),
				}
			}
		}

		#[cfg(not(feature="try_from"))]
		impl $name {
			pub fn from_repr(v: $repr) -> Option<Self> {
				match v {
					$($val => Some($name::$key),)*
					_ => None,
				}
			}
		}
	)
}

enum_def! {
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Encls {
	ECreate =  0,
	EAdd    =  1,
	EInit   =  2,
	ERemove =  3,
	EDbgrd  =  4,
	EDbgwr  =  5,
	EExtend =  6,
	ELdb    =  7,
	ELdu    =  8,
	EBlock  =  9,
	EPa     = 10,
	EWb     = 11,
	ETrack  = 12,
	EAug    = 13,
	EModpr  = 14,
	EModt   = 15,
}
}

enum_def! {
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum Enclu {
	EReport     = 0,
	EGetkey     = 1,
	EEnter      = 2,
	EResume     = 3,
	EExit       = 4,
	EAccept     = 5,
	EModpe      = 6,
	EAcceptcopy = 7,
}
}

enum_def! {
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u32)]
pub enum ErrorCode {
	Success                =   0,
	InvalidSigStruct       =   1,
	InvalidAttribute       =   2,
	Blkstate               =   3, // Blstate in §41.1.3, Blkstate in §41.3
	InvalidMeasurement     =   4,
	Notblockable           =   5,
	PgInvld                =   6,
	Lockfail               =   7,
	InvalidSignature       =   8,
	MacCompareFail         =   9,
	PageNotBlocked         =  10,
	NotTracked             =  11,
	VaSlotOccupied         =  12,
	ChildPresent           =  13,
	EnclaveAct             =  14,
	EntryepochLocked       =  15,
	InvalidEinitToken      =  16,
	PrevTrkIncmpl          =  17,
	PgIsSecs               =  18,
	PageAttributesMismatch =  19,
	PageNotModifiable      =  20,
	PageNotDebuggable      =  21,
	InvalidCpusvn          =  32,
	InvalidIsvsvn          =  64,
	UnmaskedEvent          = 128,
	InvalidKeyname         = 256,
}
}

pub const MEAS_ECREATE: u64 = 0x0045544145524345;
pub const MEAS_EADD:    u64 = 0x0000000044444145;
pub const MEAS_EEXTEND: u64 = 0x00444E4554584545;

pub const SIGSTRUCT_HEADER1: [u8; 16] = [0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const SIGSTRUCT_HEADER2: [u8; 16] = [0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];

enum_def! {
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u8)]
pub enum PageType {
	Secs = 0,
	Tcs  = 1,
	Reg  = 2,
	Va   = 3,
	Trim = 4,
}
}

enum_def! {
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u16)]
pub enum Keyname {
	EinitToken    = 0, // EinitToken in §38.17.1, Launch in §41.3
	Provision     = 1,
	ProvisionSeal = 2,
	Report        = 3,
	Seal          = 4,
}
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Secs {
	pub size:         u64,
	pub baseaddr:     u64,
	pub ssaframesize: u32,
	pub miscselect:   Miscselect,
	pub _reserved1:   [u8; 24],
	pub attributes:   Attributes,
	pub mrenclave:    [u8; 32],
	pub _reserved2:   [u8; 32],
	pub mrsigner:     [u8; 32],
	pub _reserved3:   [u8; 96],
	pub isvprodid:    u16,
	pub isvsvn:       u16,
	pub padding:      [u8; 3836],
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default,Eq,PartialEq)]
pub struct Attributes {
	pub flags: AttributesFlags,
	pub xfrm: u64,
}

pub mod attributes_flags {
	bitflags! {
		pub flags AttributesFlags: u64 {
			const INIT          = 0b0000_0001,
			const DEBUG         = 0b0000_0010,
			const MODE64BIT     = 0b0000_0100,
			const PROVISIONKEY  = 0b0001_0000,
			const EINITTOKENKEY = 0b0010_0000,
		}
	}

	impl Default for AttributesFlags {
		fn default() -> Self { Self::empty() }
	}
}
pub use self::attributes_flags::AttributesFlags;

pub mod miscselect {
	bitflags! {
		pub flags Miscselect: u32 {
			const EXINFO = 0b0000_0001,
		}
	}

	impl Default for Miscselect {
		fn default() -> Self { Self::empty() }
	}
}
pub use self::miscselect::Miscselect;

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Tcs {
	pub _reserved1: u64,
	pub flags:      TcsFlags,
	pub ossa:       u64,
	pub cssa:       u32,
	pub nssa:       u32,
	pub oentry:     u64,
	pub _reserved2: u64,
	pub ofsbasgx:   u64,
	pub ogsbasgx:   u64,
	pub fslimit:    u32,
	pub gslimit:    u32,
	pub _reserved3: [u8; 4024],
}

pub mod tcs_flags {
	bitflags! {
		pub flags TcsFlags: u64 {
			const DBGOPTIN = 0b0000_0001,
		}
	}

	impl Default for TcsFlags {
		fn default() -> Self { Self::empty() }
	}
}
pub use self::tcs_flags::TcsFlags;

#[repr(C,packed)]
#[derive(Clone,Debug,Default,Eq,PartialEq)]
pub struct Pageinfo {
	pub linaddr: u64,
	pub srcpge:  u64,
	pub secinfo: u64,
	pub secs:    u64,
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Secinfo {
	pub flags:      SecinfoFlags,
	pub _reserved1: [u8; 56],
}

pub mod secinfo_flags {
	bitflags! {
		pub flags SecinfoFlags: u64 {
			const R        = 0b0000_0000_0000_0001,
			const W        = 0b0000_0000_0000_0010,
			const X        = 0b0000_0000_0000_0100,
			const PENDING  = 0b0000_0000_0000_1000,
			const MODIFIED = 0b0000_0000_0001_0000,
			const PR       = 0b0000_0000_0010_0000,
			const PT_MASK  = 0b1111_1111_0000_0000,
			const PT_B0    = 0b0000_0001_0000_0000, // ****
			const PT_B1    = 0b0000_0010_0000_0000, // * These are just here so
			const PT_B2    = 0b0000_0100_0000_0000, // * that something shows
			const PT_B3    = 0b0000_1000_0000_0000, // * up in the Debug output
			const PT_B4    = 0b0001_0000_0000_0000, // *
			const PT_B5    = 0b0010_0000_0000_0000, // *
			const PT_B6    = 0b0100_0000_0000_0000, // *
			const PT_B7    = 0b1000_0000_0000_0000, // ****
		}
	}

	impl Default for SecinfoFlags {
		fn default() -> Self { Self::empty() }
	}

	impl SecinfoFlags {
		pub fn page_type(&self) -> u8 {
			(((*self&PT_MASK).bits) >> 8) as u8
		}

		pub fn page_type_mut(&mut self) -> &mut u8 {
			use core::mem::transmute;
			unsafe {
				let page_type: &mut [u8;8]=transmute(&mut self.bits);
				transmute(&mut page_type[1])
			}
		}
	}

	impl From<super::PageType> for SecinfoFlags {
		fn from(data: super::PageType) -> SecinfoFlags {
			SecinfoFlags::from_bits_truncate((data as u64)<<8)
		}
	}
}
pub use self::secinfo_flags::SecinfoFlags;

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Pcmd {
	pub secinfo:    Secinfo,
	pub enclaveid:  u64,
	pub _reserved1: [u8; 40],
	pub mac:        [u8; 16],
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Sigstruct {
	pub header:        [u8; 16],
	pub vendor:        u32,
	pub date:          u32,
	pub header2:       [u8; 16],
	pub swdefined:     u32,
	pub _reserved1:    [u8; 84],
	pub modulus:       [u8; 384],
	pub exponent:      u32,
	pub signature:     [u8; 384],
	pub miscselect:    Miscselect,
	pub miscmask:      u32,
	pub _reserved2:    [u8; 20],
	pub attributes:    Attributes,
	pub attributemask: [u64; 2],
	pub enclavehash:   [u8; 32],
	pub _reserved3:    [u8; 32],
	pub isvprodid:     u16,
	pub isvsvn:        u16,
	pub _reserved4:    [u8; 12],
	pub q1:            [u8; 384],
	pub q2:            [u8; 384],
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Einittoken {
	pub valid:              u32, // debug in §38.14, valid in §41.3
	pub _reserved1:         [u8; 44],
	pub attributes:         Attributes,
	pub mrenclave:          [u8; 32],
	pub _reserved2:         [u8; 32],
	pub mrsigner:           [u8; 32],
	pub _reserved3:         [u8; 32],
	pub cpusvnle:           [u8; 16],
	pub isvprodidle:        u16,
	pub isvsvnle:           u16,
	pub _reserved4:         [u8; 24],
	pub maskedmiscselectle: Miscselect,
	pub maskedattributesle: Attributes,
	pub keyid:              [u8; 32],
	pub mac:                [u8; 16],
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Report {
	pub cpusvn:     [u8; 16],
	pub miscselect: Miscselect,
	pub _reserved1: [u8; 28],
	pub attributes: Attributes,
	pub mrenclave:  [u8; 32],
	pub _reserved2: [u8; 32],
	pub mrsigner:   [u8; 32],
	pub _reserved3: [u8; 96],
	pub isvprodid:  u16,
	pub isvsvn:     u16,
	pub _reserved4: [u8; 60],
	pub reportdata: [u8; 64],
	pub keyid:      [u8; 32],
	pub mac:        [u8; 16],
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Targetinfo {
	pub measurement: [u8; 32],
	pub attributes:  Attributes,
	pub _reserved1:  [u8; 4],
	pub miscselect:  Miscselect,
	pub _reserved2:  [u8; 456],
}

impl From<Report> for Targetinfo {
	fn from(r: Report) -> Targetinfo {
		Targetinfo{
			measurement: r.mrenclave,
			attributes: r.attributes,
			miscselect: r.miscselect,
			..Targetinfo::default()
		}
	}
}

#[repr(C,packed)]
#[cfg_attr(feature="large_array_derive",derive(Clone,Debug,Default,Eq,PartialEq))]
pub struct Keyrequest {
	pub keyname:       u16,
	pub keypolicy:     Keypolicy,
	pub isvsvn:        u16,
	pub _reserved1:    u16,
	pub cpusvn:        [u8; 16],
	pub attributemask: [u64; 2],
	pub keyid:         [u8; 32],
	pub miscmask:      u32,
	pub _reserved2:    [u8; 436],
}

pub mod keypolicy {
	bitflags! {
		pub flags Keypolicy: u16 {
			const MRENCLAVE = 0b0000_0001,
			const MRSIGNER  = 0b0000_0010,
		}
	}

	impl Default for Keypolicy {
		fn default() -> Self { Self::empty() }
	}
}
pub use self::keypolicy::Keypolicy;

#[cfg(not(feature="large_array_derive"))]
mod large_array_impl;

#[test]
fn test_eq() {
	let mut a = Keyrequest::default();
	let mut b = Keyrequest::default();
	assert!(a == b);

	a.keyname = 22;
	assert!(a != b);

	b.keyname = 22;
	assert!(a == b);

	a.miscmask = 0xdeadbeef;
	assert!(a != b);

	b.miscmask = 0xdeadbeef;
	assert!(a == b);
}
