/* Copyright (c) Jethro G. Beekman and Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
//! Constants and structures related to the Intel SGX ISA extension.
//!
//! These are taken directly from the [Intel Software Developer's Manual][isdm],
//! volume 3, chapters 37–43. Rust conversions traits were added where
//! convenient.
//!
//! [isdm]: https://www-ssl.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html

#![no_std]
#![cfg_attr(feature = "try_from", feature(try_from))]

#[macro_use]
extern crate bitflags;

#[cfg(not(feature = "large_array_derive"))]
#[macro_use]
mod large_array_impl;
#[cfg(feature = "large_array_derive")]
macro_rules! impl_default_clone_eq { ($n:ident) => {} }

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
			type Error = ::core::num::TryFromIntError;
			fn try_from(v: $repr) -> Result<Self, Self::Error> {
				match v {
					$($val => Ok($name::$key),)*
					_ => Err(u8::try_from(256u16).unwrap_err()),
				}
			}
		}

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

macro_rules! struct_def {
    (
        #[repr(C $(, align($align:expr))*)]
        $(#[cfg_attr(feature = "large_array_derive", derive($($cfgderive:meta),*))])*
        $(#[derive($($derive:meta),*)])*
        pub struct $name:ident $impl:tt
    ) => {
        $(
            impl_default_clone_eq!($name);
            #[cfg_attr(feature = "large_array_derive", derive($($cfgderive),*))]
        )*
        #[repr(C $(, align($align))*)]
        $(#[derive($($derive),*)])*
        pub struct $name $impl

        impl $name {
			/// If `src` has the correct length for this type, returns `Some<T>`
			/// copied from `src`, else returns `None`.
			pub fn try_copy_from(src: &[u8]) -> Option<Self> {
				if src.len() == Self::UNPADDED_SIZE {
					unsafe {
                        let mut ret : Self = ::core::mem::zeroed();
                        ::core::ptr::copy_nonoverlapping(src.as_ptr(),
                                                         &mut ret as *mut _ as *mut _,
                                                         Self::UNPADDED_SIZE);
						Some(ret)
					}
				} else {
					None
				}
			}

            // Compile time check that the size argument is correct.
            // Not otherwise used.
            fn _type_tests() {
                #[repr(C)]
                struct _Unaligned $impl

                impl _Unaligned {
                    unsafe fn _check_size(self) -> [u8; $name::UNPADDED_SIZE] {
                        ::core::mem::transmute(self)
                    }
                }
            }
		}

        $(
        // check that alignment is set correctly
        #[test]
        #[allow(non_snake_case)]
        fn $name() {
            assert_eq!($align, ::core::mem::align_of::<$name>());
        }
        )*

		impl AsRef<[u8]> for $name {
			fn as_ref(&self) -> &[u8] {
				unsafe {
					::core::slice::from_raw_parts(self as *const $name as *const u8, Self::UNPADDED_SIZE)
				}
			}
		}
    };
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
    Blkstate               =   3, // Blstate in §40.1.4, Blkstate in §40.3
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
pub const MEAS_EADD: u64 = 0x0000000044444145;
pub const MEAS_EEXTEND: u64 = 0x00444E4554584545;

pub const SIGSTRUCT_HEADER1: [u8; 16] = [
    0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub const SIGSTRUCT_HEADER2: [u8; 16] = [
    0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];

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
    Einittoken    = 0,
    Provision     = 1,
    ProvisionSeal = 2,
    Report        = 3,
    Seal          = 4,
}
}

struct_def! {
#[repr(C, align(4096))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Secs {
    pub size: u64,
    pub baseaddr: u64,
    pub ssaframesize: u32,
    pub miscselect: Miscselect,
    pub _reserved1: [u8; 24],
    pub attributes: Attributes,
    pub mrenclave: [u8; 32],
    pub _reserved2: [u8; 32],
    pub mrsigner: [u8; 32],
    pub _reserved3: [u8; 96],
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub padding: [u8; 3836],
}
}

impl Secs {
    pub const UNPADDED_SIZE: usize = 4096;
}

struct_def! {
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attributes {
    pub flags: AttributesFlags,
    pub xfrm: u64,
}
}

impl Attributes {
    pub const UNPADDED_SIZE: usize = 16;
}

bitflags! {
    #[repr(C)]
    pub struct AttributesFlags: u64 {
        const INIT          = 0b0000_0001;
        const DEBUG         = 0b0000_0010;
        const MODE64BIT     = 0b0000_0100;
        const PROVISIONKEY  = 0b0001_0000;
        const EINITTOKENKEY = 0b0010_0000;
    }
}

impl Default for AttributesFlags {
    fn default() -> Self {
        Self::empty()
    }
}

bitflags! {
    #[repr(C)]
    pub struct Miscselect: u32 {
        const EXINFO = 0b0000_0001;
    }
}

impl Default for Miscselect {
    fn default() -> Self {
        Self::empty()
    }
}

struct_def! {
#[repr(C, align(4096))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Tcs {
    pub _reserved1: u64,
    pub flags: TcsFlags,
    pub ossa: u64,
    pub cssa: u32,
    pub nssa: u32,
    pub oentry: u64,
    pub _reserved2: u64,
    pub ofsbasgx: u64,
    pub ogsbasgx: u64,
    pub fslimit: u32,
    pub gslimit: u32,
    pub _reserved3: [u8; 4024],
}
}

impl Tcs {
    pub const UNPADDED_SIZE: usize = 4096;
}

bitflags! {
    #[repr(C)]
    pub struct TcsFlags: u64 {
        const DBGOPTIN = 0b0000_0001;
    }
}

impl Default for TcsFlags {
    fn default() -> Self {
        Self::empty()
    }
}

struct_def! {
#[repr(C, align(32))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Pageinfo {
    pub linaddr: u64,
    pub srcpge: u64,
    pub secinfo: u64,
    pub secs: u64,
}
}

impl Pageinfo {
    pub const UNPADDED_SIZE: usize = 32;
}

struct_def! {
#[repr(C, align(64))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Secinfo {
    pub flags: SecinfoFlags,
    pub _reserved1: [u8; 56],
}
}

impl Secinfo {
    pub const UNPADDED_SIZE: usize = 64;
}

bitflags! {
    #[repr(C)]
    pub struct SecinfoFlags: u64 {
        const R        = 0b0000_0000_0000_0001;
        const W        = 0b0000_0000_0000_0010;
        const X        = 0b0000_0000_0000_0100;
        const PENDING  = 0b0000_0000_0000_1000;
        const MODIFIED = 0b0000_0000_0001_0000;
        const PR       = 0b0000_0000_0010_0000;
        const PT_MASK  = 0b1111_1111_0000_0000;
        const PT_B0    = 0b0000_0001_0000_0000; // ****
        const PT_B1    = 0b0000_0010_0000_0000; // * These are just here so
        const PT_B2    = 0b0000_0100_0000_0000; // * that something shows
        const PT_B3    = 0b0000_1000_0000_0000; // * up in the Debug output
        const PT_B4    = 0b0001_0000_0000_0000; // *
        const PT_B5    = 0b0010_0000_0000_0000; // *
        const PT_B6    = 0b0100_0000_0000_0000; // *
        const PT_B7    = 0b1000_0000_0000_0000; // ****
    }
}

impl Default for SecinfoFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl SecinfoFlags {
    pub fn page_type(&self) -> u8 {
        (((*self & SecinfoFlags::PT_MASK).bits) >> 8) as u8
    }

    pub fn page_type_mut(&mut self) -> &mut u8 {
        use core::mem::transmute;
        unsafe {
            let page_type: &mut [u8; 8] = transmute(&mut self.bits);
            transmute(&mut page_type[1])
        }
    }
}

impl From<PageType> for SecinfoFlags {
    fn from(data: PageType) -> SecinfoFlags {
        SecinfoFlags::from_bits_truncate((data as u64) << 8)
    }
}

struct_def! {
#[repr(C, align(128))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Pcmd {
    pub secinfo: Secinfo,
    pub enclaveid: u64,
    pub _reserved1: [u8; 40],
    pub mac: [u8; 16],
}
}

impl Pcmd {
    pub const UNPADDED_SIZE: usize = 128;
}

struct_def! {
#[repr(C, align(4096))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Sigstruct {
    pub header: [u8; 16],
    pub vendor: u32,
    pub date: u32,
    pub header2: [u8; 16],
    pub swdefined: u32,
    pub _reserved1: [u8; 84],
    pub modulus: [u8; 384],
    pub exponent: u32,
    pub signature: [u8; 384],
    pub miscselect: Miscselect,
    pub miscmask: u32,
    pub _reserved2: [u8; 20],
    pub attributes: Attributes,
    pub attributemask: [u64; 2],
    pub enclavehash: [u8; 32],
    pub _reserved3: [u8; 32],
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub _reserved4: [u8; 12],
    pub q1: [u8; 384],
    pub q2: [u8; 384],
}
}

impl Sigstruct {
    pub const UNPADDED_SIZE: usize = 1808;
}

struct_def! {
#[repr(C, align(512))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Einittoken {
    pub valid: u32,
    pub _reserved1: [u8; 44],
    pub attributes: Attributes,
    pub mrenclave: [u8; 32],
    pub _reserved2: [u8; 32],
    pub mrsigner: [u8; 32],
    pub _reserved3: [u8; 32],
    pub cpusvnle: [u8; 16],
    pub isvprodidle: u16,
    pub isvsvnle: u16,
    pub _reserved4: [u8; 24],
    pub maskedmiscselectle: Miscselect,
    pub maskedattributesle: Attributes,
    pub keyid: [u8; 32],
    pub mac: [u8; 16],
}
}

impl Einittoken {
    pub const UNPADDED_SIZE: usize = 304;
}

struct_def! {
#[repr(C, align(512))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Report {
    pub cpusvn: [u8; 16],
    pub miscselect: Miscselect,
    pub _reserved1: [u8; 28],
    pub attributes: Attributes,
    pub mrenclave: [u8; 32],
    pub _reserved2: [u8; 32],
    pub mrsigner: [u8; 32],
    pub _reserved3: [u8; 96],
    pub isvprodid: u16,
    pub isvsvn: u16,
    pub _reserved4: [u8; 60],
    pub reportdata: [u8; 64],
    pub keyid: [u8; 32],
    pub mac: [u8; 16],
}
}

impl Report {
    pub const UNPADDED_SIZE: usize = 432;
}

struct_def! {
#[repr(C, align(512))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Targetinfo {
    pub measurement: [u8; 32],
    pub attributes: Attributes,
    pub _reserved1: [u8; 4],
    pub miscselect: Miscselect,
    pub _reserved2: [u8; 456],
}
}

impl Targetinfo {
    pub const UNPADDED_SIZE: usize = 512;
}

impl From<Report> for Targetinfo {
    fn from(r: Report) -> Targetinfo {
        Targetinfo {
            measurement: r.mrenclave,
            attributes: r.attributes,
            miscselect: r.miscselect,
            ..Targetinfo::default()
        }
    }
}

struct_def! {
#[repr(C, align(512))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
pub struct Keyrequest {
    pub keyname: u16,
    pub keypolicy: Keypolicy,
    pub isvsvn: u16,
    pub _reserved1: u16,
    pub cpusvn: [u8; 16],
    pub attributemask: [u64; 2],
    pub keyid: [u8; 32],
    pub miscmask: u32,
    pub _reserved2: [u8; 436],
}
}

impl Keyrequest {
    pub const UNPADDED_SIZE: usize = 512;
}

bitflags! {
    #[repr(C)]
    pub struct Keypolicy: u16 {
        const MRENCLAVE = 0b0000_0001;
        const MRSIGNER  = 0b0000_0010;
    }
}

impl Default for Keypolicy {
    fn default() -> Self {
        Self::empty()
    }
}

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
