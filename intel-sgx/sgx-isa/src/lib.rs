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
#![cfg_attr(feature = "nightly", feature(llvm_asm))]

#![no_std]
#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]
#![cfg_attr(all(feature = "sgxstd", target_env = "sgx"), feature(sgx_platform))]

#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
extern crate std;

#[macro_use]
extern crate bitflags;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

#[cfg(all(feature = "sgxstd", target_env = "sgx"))]
use std::os::fortanix_sgx::arch;
#[cfg(all(feature = "nightly", target_env = "sgx", not(feature = "sgxstd")))]
mod arch;
use core::{convert::TryFrom, num::TryFromIntError, slice};


#[cfg(feature = "serde")]
mod array_64 {
    use serde::{
        de::{Deserializer, Error, SeqAccess, Visitor},
        ser::{SerializeTuple, Serializer},
    };
    use core::fmt;

    const LEN: usize = 64;

    pub fn serialize<S: Serializer>(array: &[u8; LEN], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_tuple(LEN)?;
        for elem in &array[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; LEN], D::Error> {
        struct ArrayVisitor;
        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = [u8; LEN];
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length 64")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; LEN], A::Error> {
                let mut arr = [0; LEN];
                for i in 0..LEN {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_tuple(64, ArrayVisitor)
    }
}

// These helper functions implement defaults for structs' reserved fields,
// which is necessary for serde support.
#[cfg(feature = "serde")]
fn report_reserved1() -> [u8; 28] {
    [0u8; 28]
}

#[cfg(feature = "serde")]
fn report_reserved2() -> [u8; 32] {
    [0u8; 32]
}

#[cfg(feature = "serde")]
fn report_reserved3() -> [u8; 96] {
    [0u8; 96]
}

#[cfg(feature = "serde")]
fn report_reserved4() -> [u8; 60] {
    [0u8; 60]
}

#[cfg(feature = "serde")]
fn ti_reserved1() -> [u8; 4] {
    [0u8; 4]
}

#[cfg(feature = "serde")]
fn ti_reserved2() -> [u8; 456] {
    [0u8; 456]
}

#[cfg(not(feature = "large_array_derive"))]
#[macro_use]
mod large_array_impl;
#[cfg(feature = "large_array_derive")]
macro_rules! impl_default_clone_eq {
    ($n:ident) => {};
}

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

        impl TryFrom<$repr> for $name {
            type Error = TryFromIntError;
            fn try_from(v: $repr) -> Result<Self, Self::Error> {
                match v {
                    $($val => Ok($name::$key),)*
                    _ => Err(u8::try_from(256u16).unwrap_err()),
                }
            }
        }
    )
}

macro_rules! struct_def {
    (
        #[repr(C $(, align($align:tt))*)]
        $(#[cfg_attr(feature = "large_array_derive", derive($($cfgderive:meta),*))])*
        $(#[cfg_attr(feature = "serde", derive($($serdederive:meta),*))])*
        $(#[derive($($derive:meta),*)])*
        pub struct $name:ident $impl:tt
    ) => {
        $(
            impl_default_clone_eq!($name);
            #[cfg_attr(feature = "large_array_derive", derive($($cfgderive),*))]
        )*
        #[repr(C $(, align($align))*)]
        $(#[cfg_attr(feature = "serde", derive($($serdederive),*))])*
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
                $(#[cfg_attr(feature = "serde", derive($($serdederive),*))])*
                struct _Unaligned $impl

                impl _Unaligned {
                    unsafe fn _check_size(self) -> [u8; $name::UNPADDED_SIZE] {
                        ::core::mem::transmute(self)
                    }
                }

                // Should also check packed size against unaligned size here,
                // but Rust doesn't allow packed structs to contain aligned
                // structs, so this can't be tested.
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
                    slice::from_raw_parts(self as *const $name as *const u8, Self::UNPADDED_SIZE)
                }
            }
        }

        struct_def!(@align bytes $($align)* name $name);
    };
    (@align bytes 16 name $name:ident) => {
        struct_def!(@align type Align16 name $name);
    };
    (@align bytes 128 name $name:ident) => {
        struct_def!(@align type Align128 name $name);
    };
    (@align bytes 512 name $name:ident) => {
        struct_def!(@align type Align512 name $name);
    };
    (@align bytes $($other:tt)*) => {};
    (@align type $ty:ident name $name:ident) => {
        #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
        /// **Note.** This implementation is only available on the SGX target
        /// with the `sgxstd` feature.
        impl AsRef<arch::$ty<[u8; $name::UNPADDED_SIZE]>> for $name {
            fn as_ref(&self) -> &arch::$ty<[u8; $name::UNPADDED_SIZE]> {
                unsafe {
                    &*(self as *const _ as *const _)
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct AttributesFlags: u64 {
        const INIT          = 0b0000_0001;
        const DEBUG         = 0b0000_0010;
        const MODE64BIT     = 0b0000_0100;
        const PROVISIONKEY  = 0b0001_0000;
        const EINITTOKENKEY = 0b0010_0000;
        const CET           = 0b0100_0000;
        const KSS           = 0b1000_0000;
    }
}

impl Default for AttributesFlags {
    fn default() -> Self {
        Self::empty()
    }
}

bitflags! {
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

    /// Returns that part of the `Sigstruct` that is signed. The returned
    /// slices should be concatenated for hashing.
    pub fn signature_data(&self) -> (&[u8], &[u8]) {
        unsafe {
            let part1_start = &(self.header) as *const _ as *const u8;
            let part1_end = &(self.modulus) as *const _ as *const u8 as usize;
            let part2_start = &(self.miscselect) as *const _ as *const u8;
            let part2_end = &(self._reserved4) as *const _ as *const u8 as usize;

            (
                slice::from_raw_parts(part1_start, part1_end - (part1_start as usize)),
                slice::from_raw_parts(part2_start, part2_end - (part2_start as usize))
            )
        }
    }
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Report {
    pub cpusvn: [u8; 16],
    pub miscselect: Miscselect,
    #[cfg_attr(feature = "serde", serde(default = "report_reserved1"), serde(skip))]
    pub _reserved1: [u8; 28],
    pub attributes: Attributes,
    pub mrenclave: [u8; 32],
    #[cfg_attr(feature = "serde", serde(default = "report_reserved2"), serde(skip))]
    pub _reserved2: [u8; 32],
    pub mrsigner: [u8; 32],
    #[cfg_attr(feature = "serde", serde(default = "report_reserved3"), serde(skip))]
    pub _reserved3: [u8; 96],
    pub isvprodid: u16,
    pub isvsvn: u16,
    #[cfg_attr(feature = "serde", serde(default = "report_reserved4"), serde(skip))]
    pub _reserved4: [u8; 60],
    #[cfg_attr(feature = "serde", serde(with = "array_64"))]
    pub reportdata: [u8; 64],
    pub keyid: [u8; 32],
    pub mac: [u8; 16],
}
}

impl Report {
    pub const UNPADDED_SIZE: usize = 432;
    /// Report size without keyid and mac
    pub const TRUNCATED_SIZE: usize = 384;

    /// Generate a bogus report that can be used to obtain one's own
    /// `Targetinfo`.
    ///
    /// # Examples
    /// ```
    /// use sgx_isa::{Report, Targetinfo};
    ///
    /// let targetinfo_self = Targetinfo::from(Report::for_self());
    /// ```
    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn for_self() -> Self {
        let reportdata = arch::Align128([0; 64]);
        let targetinfo = arch::Align512([0; 512]);
        let out = arch::ereport(&targetinfo, &reportdata);
        // unwrap ok, `out` is the correct number of bytes
        Report::try_copy_from(&out.0).unwrap()
    }

    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn for_target(targetinfo: &Targetinfo, reportdata: &[u8; 64]) -> Report {
        let reportdata = arch::Align128(*reportdata);
        let out = arch::ereport(targetinfo.as_ref(), &reportdata);
        // unwrap ok, `out` is the correct number of bytes
        Report::try_copy_from(&out.0).unwrap()
    }

    /// This function verifies the report's MAC using the provided
    /// implementation of the verifying function.
    ///
    /// Care should be taken that `check_mac` prevents timing attacks,
    /// in particular that the comparison happens in constant time. 
    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn verify<F, R>(&self, check_mac: F) -> R
    where
        F: FnOnce(&[u8; 16], &[u8; Report::TRUNCATED_SIZE], &[u8; 16]) -> R,
    {
        let req = Keyrequest {
            keyname: Keyname::Report as u16,
            keyid: self.keyid,
            ..Default::default()
        };
        let key = req.egetkey().expect("Couldn't get report key");
        check_mac(
            &key,
            self.mac_data(),
            &self.mac,
        )
    }

    /// Returns that part of the `Report` that is MACed.
    pub fn mac_data(&self) -> &[u8; Report::TRUNCATED_SIZE] {
        unsafe {
            &*(self as *const Self as *const [u8; Report::TRUNCATED_SIZE])
        }
    }
}

struct_def! {
#[repr(C, align(512))]
#[cfg_attr(
    feature = "large_array_derive",
    derive(Clone, Debug, Default, Eq, PartialEq)
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Targetinfo {
    pub measurement: [u8; 32],
    pub attributes: Attributes,
    #[cfg_attr(feature = "serde", serde(default = "ti_reserved1"), serde(skip))]
    pub _reserved1: [u8; 4],
    pub miscselect: Miscselect,
    #[cfg_attr(feature = "serde", serde(default = "ti_reserved2"), serde(skip))]
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

    #[cfg(all(feature = "sgxstd", target_env = "sgx"))]
    pub fn egetkey(&self) -> Result<[u8; 16], ErrorCode> {
        match arch::egetkey(self.as_ref()) {
            Ok(k) => Ok(k.0),
            // unwrap ok, `arch::egetkey` will always return a valid `ErrorCode`
            Err(e) => Err(ErrorCode::try_from(e).unwrap())
        }
    }
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
