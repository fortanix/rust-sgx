/*
 * The Intel SGX ABI.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#![allow(dead_code)]

use core::mem::transmute;

#[derive(Clone,Copy,Debug)]
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

#[derive(Clone,Copy,Debug)]
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

#[derive(Clone,Copy,Debug)]
#[repr(u32)]
pub enum ErrorCodes {
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

pub const MEAS_ECREATE: u64 = 0x0045544145524345;
pub const MEAS_EADD:    u64 = 0x0000000044444145;
pub const MEAS_EEXTEND: u64 = 0x00444E4554584545;

pub const SIGSTRUCT_HEADER1: [u8; 16] = [0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
pub const SIGSTRUCT_HEADER2: [u8; 16] = [0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
#[repr(u8)]
pub enum PageType {
	Secs = 0,
	Tcs  = 1,
	Reg  = 2,
	Va   = 3,
	Trim = 4,
}

#[derive(Clone,Copy,Debug)]
#[repr(u16)]
pub enum KeyName {
	Launch        = 0,
	Provision     = 1,
	ProvisionSeal = 2,
	Report        = 3,
	Seal          = 4,
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
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

impl Default for Secs {
	fn default() -> Secs {
		unsafe{transmute([0u8;4096])}
	}
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct Attributes {
	pub flags: AttributesFlags,
	pub xfrm: u64,
}

bitflags! {
	flags AttributesFlags: u64 {
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

bitflags! {
	flags Miscselect: u32 {
		const EXINFO = 0b0000_0001,
	}
}

impl Default for Miscselect {
	fn default() -> Self { Self::empty() }
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
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

impl Default for Tcs {
	fn default() -> Tcs {
		unsafe{transmute([0u8;4096])}
	}
}

bitflags! {
	flags TcsFlags: u64 {
		const DBGOPTIN = 0b0000_0001,
	}
}

impl Default for TcsFlags {
	fn default() -> Self { Self::empty() }
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct Pageinfo {
	pub linaddr: u64,
	pub srcpge:  u64,
	pub secinfo: u64,
	pub secs:    u64,
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub struct Secinfo {
	pub flags:      SecinfoFlags,
	pub _reserved1: [u8; 56],
}

impl Default for Secinfo {
	fn default() -> Secinfo {
		unsafe{transmute([0u8;64])}
	}
}

pub mod secinfo_flags {
	use super::PageType;
	use core::mem::transmute;

	bitflags! {
		flags SecinfoFlags: u64 {
			const R        = 0b0000_0000_0000_0001,
			const W        = 0b0000_0000_0000_0010,
			const X        = 0b0000_0000_0000_0100,
			const PENDING  = 0b0000_0000_0000_1000,
			const MODIFIED = 0b0000_0000_0001_0000,
			const PR       = 0b0000_0000_0010_0000,
			const PT_MASK  = 0b1111_1111_0000_0000,
			const PT_B0    = 0b0000_0001_0000_0000, // ****
			const PT_B1    = 0b0000_0010_0000_0000, // * These are just here so that
			const PT_B2    = 0b0000_0100_0000_0000, // * something shows up in the
			const PT_B3    = 0b0000_1000_0000_0000, // * Debug output
			const PT_B4    = 0b0001_0000_0000_0000, // *
			const PT_B5    = 0b0010_0000_0000_0000, // *
			const PT_B6    = 0b0100_0000_0000_0000, // *
			const PT_B7    = 0b1000_0000_0000_0000, // ****
		}
	}

	impl SecinfoFlags {
		pub fn page_type(&self) -> PageType {
			unsafe{transmute((((*self&PT_MASK).bits) >> 8) as u8)}
		}

		pub fn page_type_mut(&mut self) -> &mut PageType {
			unsafe {
				let page_type: &mut [u8;8]=transmute(&mut self.bits);
				transmute(&mut page_type[1])
			}
		}
	}

	impl From<PageType> for SecinfoFlags {
		fn from(data: PageType) -> SecinfoFlags {
			SecinfoFlags::from_bits_truncate((data as u64)<<8)
		}
	}

	impl Default for SecinfoFlags {
		fn default() -> Self { Self::empty() }
	}
}

pub use self::secinfo_flags::SecinfoFlags;

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub struct Pcmd {
	pub secinfo:    Secinfo,
	pub enclaveid:  u64,
	pub _reserved1: [u8; 40],
	pub mac:        [u8; 2],
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
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
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub struct Einittoken {
	pub valid:              u32,
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

impl Default for Einittoken {
	fn default() -> Einittoken {
		unsafe{transmute([0u8;304])}
	}
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
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
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub struct Targetinfo {
	pub measurement: [u8; 32],
	pub attributes:  Attributes,
	pub _reserved1:  [u8; 4],
	pub miscselect:  Miscselect,
	pub _reserved2:  [u8; 456],
}

impl Default for Targetinfo {
	fn default() -> Targetinfo {
		unsafe{transmute([0u8;512])}
	}
}

#[repr(C,packed)]
// Doesn't work because large array: #[derive(Clone,Debug,Default)]
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

impl Default for Keyrequest {
	fn default() -> Keyrequest {
		unsafe{transmute([0u8;512])}
	}
}

bitflags! {
	flags Keypolicy: u16 {
		const MRENCLAVE = 0b0000_0001,
		const MRSIGNER  = 0b0000_0010,
	}
}

impl Default for Keypolicy {
	fn default() -> Self { Self::empty() }
}
