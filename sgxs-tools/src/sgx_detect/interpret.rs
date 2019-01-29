//! Interpreting raw values returned from the environment

use std::arch::x86_64::CpuidResult;
use std::io;

use byteorder::{ReadBytesExt, LE};

use sgx_isa::{AttributesFlags, Miscselect};

fn check_bit_32(mut value: u32, bit: u8) -> bool {
    check_bit_erase_32(&mut value, bit)
}

fn check_bit_erase_32(value: &mut u32, bit: u8) -> bool {
    let bit = 1 << bit;
    let ret = (*value & bit) != 0;
    if ret {
        *value ^= bit;
    }
    ret
}

fn check_bit_64(value: u64, bit: u8) -> bool {
    (value & (1 << bit)) != 0
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Cpuid7h {
    pub sgx: bool,
    pub sgx_lc: bool,
}

impl From<CpuidResult> for Cpuid7h {
    fn from(v: CpuidResult) -> Self {
        // See Intel SDM, Volume 2, Chapter 3, “CPUID”, Leaf 07h
        Cpuid7h {
            sgx: check_bit_32(v.ebx, 2),
            sgx_lc: check_bit_32(v.ecx, 30),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Cpuid12h0 {
    pub sgx1: bool,
    pub sgx2: bool,
    pub enclv: bool,
    pub oversub: bool,
    #[serde(with = "serde::miscselect")]
    pub miscselect_valid: Miscselect,
    pub max_enclave_size_32: u64,
    pub max_enclave_size_64: u64,
}

impl From<CpuidResult> for Cpuid12h0 {
    fn from(mut v: CpuidResult) -> Self {
        // See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
        let ret = Cpuid12h0 {
            sgx1: check_bit_erase_32(&mut v.eax, 0),
            sgx2: check_bit_erase_32(&mut v.eax, 1),
            enclv: check_bit_erase_32(&mut v.eax, 5),
            oversub: check_bit_erase_32(&mut v.eax, 6),
            miscselect_valid: Miscselect::from_bits_truncate(v.ebx),
            max_enclave_size_32: 1 << (v.edx as u8),
            max_enclave_size_64: 1 << ((v.edx >> 8) as u8),
        };
        if v.eax != 0 {
            warn!(
                "CPUID 12h, sub-leaf 0 EAX has reserved bits set: {:08x}",
                v.eax
            );
        }
        if (v.ebx ^ ret.miscselect_valid.bits()) != 0 {
            warn!(
                "CPUID 12h, sub-leaf 0 EBX (MISCSELECT) has reserved bits set: {:08x}",
                v.ebx ^ ret.miscselect_valid.bits()
            );
        }
        if v.ecx != 0 {
            warn!(
                "CPUID 12h, sub-leaf 0 ECX has reserved bits set: {:08x}",
                v.ecx
            );
        }
        if (v.edx & !0xffff) != 0 {
            warn!(
                "CPUID 12h, sub-leaf 0 EDX has reserved bits set: {:08x}",
                v.edx & !0xffff
            );
        }
        ret
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Cpuid12h1 {
    #[serde(with = "serde::attributes_flags")]
    pub attributes_flags_valid: AttributesFlags,
    pub attributes_xfrm_valid: u64,
}

impl From<CpuidResult> for Cpuid12h1 {
    fn from(v: CpuidResult) -> Self {
        // See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
        let attributes_flags = (v.eax as u64) | ((v.ebx as u64) << 32);
        let ret = Cpuid12h1 {
            attributes_flags_valid: AttributesFlags::from_bits_truncate(attributes_flags),
            attributes_xfrm_valid: (v.ecx as u64) | ((v.edx as u64) << 32),
        };
        if (attributes_flags ^ ret.attributes_flags_valid.bits()) != 0 {
            warn!(
                "CPUID 12h, sub-leaf 1 EBX:EAX (ATTRIBUTES.FLAGS) has reserved bits set: {:016x}",
                attributes_flags ^ ret.attributes_flags_valid.bits()
            );
        }
        ret
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EpcType {
    Invalid,
    ConfidentialityIntegrityProtected,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Cpuid12hEnum {
    Invalid,
    Epc {
        ty: EpcType,
        phys_base: u64,
        phys_size: u64,
    },
    Unknown,
}

impl From<(u32, CpuidResult)> for Cpuid12hEnum {
    fn from((subleaf, v): (u32, CpuidResult)) -> Self {
        // See Intel SDM, Volume 3, Chapter 36, Section 7, “Discovering Support for Intel SGX”
        match v.eax & 0xf {
            0 => Cpuid12hEnum::Invalid,
            1 => {
                // EPC section
                // SDM documentation somewhat unclear on this field (referring to EAX[3:0])
                let ty = match v.ecx & 0xf {
                    0 => EpcType::Invalid,
                    1 => EpcType::ConfidentialityIntegrityProtected,
                    n => {
                        warn!("CPUID 12h, sub-leaf {} (EPC section) unknown EPC type: {:x}h. EAX={:08x}, EBX={:08x}, ECX={:08x}, EDX={:08x}", subleaf, n, v.eax, v.ebx, v.ecx, v.edx);
                        EpcType::Unknown
                    }
                };
                let ret = Cpuid12hEnum::Epc {
                    ty,
                    phys_base: ((v.ebx as u64 & 0xf_fffff) << 32) | (v.eax as u64 & 0xffff_f000),
                    phys_size: ((v.edx as u64 & 0xf_fffff) << 32) | (v.ecx as u64 & 0xffff_f000),
                };
                if (v.eax & 0xff0) != 0 {
                    warn!(
                        "CPUID 12h, sub-leaf {} EAX has reserved bits set: {:08x}",
                        subleaf,
                        v.eax & 0xff0
                    );
                }
                if (v.ebx & 0xfff0_0000) != 0 {
                    warn!(
                        "CPUID 12h, sub-leaf {} EBX has reserved bits set: {:08x}",
                        subleaf,
                        v.ebx & 0xfff0_0000
                    );
                }
                if (v.ecx & 0xff0) != 0 {
                    warn!(
                        "CPUID 12h, sub-leaf {} ECX has reserved bits set: {:08x}",
                        subleaf,
                        v.ecx & 0xff0
                    );
                }
                if (v.edx & 0xfff0_0000) != 0 {
                    warn!(
                        "CPUID 12h, sub-leaf {} EDX has reserved bits set: {:08x}",
                        subleaf,
                        v.edx & 0xfff0_0000
                    );
                }
                ret
            }
            n => {
                warn!("CPUID 12h, sub-leaf {} unknown section type: {:x}h. EAX={:08x}, EBX={:08x}, ECX={:08x}, EDX={:08x}", subleaf, n, v.eax, v.ebx, v.ecx, v.edx);
                Cpuid12hEnum::Unknown
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Msr3ah {
    pub locked: bool,
    pub sgx: bool,
    pub sgx_lc: bool,
}

impl From<u64> for Msr3ah {
    fn from(v: u64) -> Self {
        // See Intel SDM, Volume 4, Chapter 2, Section 1, “Architectural MSRs”, Address 3Ah
        Msr3ah {
            locked: check_bit_64(v, 0),
            sgx_lc: check_bit_64(v, 17),
            sgx: check_bit_64(v, 18),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct EfiEpcbios {
    pub prm_bins: u32,
    pub max_epc_size: u32,
    pub current_epc_size: u32,
    pub epc_map: [u32; 32],
}

impl From<Vec<u8>> for EfiEpcbios {
    fn from(v: Vec<u8>) -> Self {
        if v.len() != std::mem::size_of::<Self>() {
            warn!("Invalid size for EPCBIOS EFI variable: {}", v.len());
        }
        let mut v = &v[..];
        (|| -> Result<_, io::Error> {
            Ok(EfiEpcbios {
                prm_bins: v.read_u32::<LE>()?,
                max_epc_size: v.read_u32::<LE>()?,
                current_epc_size: v.read_u32::<LE>()?,
                epc_map: {
                    let mut map = [0u32; 32];
                    for elem in &mut map {
                        *elem = v.read_u32::<LE>()?;
                    }
                    map
                },
            })
        })()
        .unwrap_or_default()
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct EfiEpcsw {
    pub epc_size: u32,
}

impl From<Vec<u8>> for EfiEpcsw {
    fn from(v: Vec<u8>) -> Self {
        if v.len() != std::mem::size_of::<Self>() {
            warn!("Invalid size for EPCSW EFI variable: {}", v.len());
        }
        let mut v = &v[..];
        (|| -> Result<_, io::Error> {
            Ok(EfiEpcsw {
                epc_size: v.read_u32::<LE>()?,
            })
        })()
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SgxEnableStatus {
    Disabled,
    Enabled,
    SoftwareControlled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EfiSoftwareguardstatus {
    pub status: SgxEnableStatus,
}

impl From<Vec<u8>> for EfiSoftwareguardstatus {
    fn from(v: Vec<u8>) -> Self {
        if v.len() != std::mem::size_of::<Self>() {
            warn!(
                "Invalid size for SOFTWAREGUARDSTATUS EFI variable: {}",
                v.len()
            );
        }
        let status = v.get(0).map(|v| v & 0b11);
        let reserved = v.get(0).map(|v| v & !0b11);
        let ret = EfiSoftwareguardstatus {
            status: match status {
                Some(0) => SgxEnableStatus::Disabled,
                Some(1) => SgxEnableStatus::Enabled,
                Some(2) => SgxEnableStatus::SoftwareControlled,
                Some(v) => {
                    warn!("EFI variable SOFTWAREGUARDSTATUS: invalid status {:x}", v);
                    SgxEnableStatus::Unknown
                }
                None => SgxEnableStatus::Unknown,
            },
        };
        match reserved {
            None | Some(0) => {}
            Some(v) => warn!(
                "EFI variable SOFTWAREGUARDSTATUS: invalid reserved bits: {:x}",
                v
            ),
        }
        ret
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AesmStatus {
    Absent,
    Installed,
    Running
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KmodStatus {
    pub loaded: Vec<String>,
    pub available: Vec<String>,
}

mod serde {
    pub mod miscselect {
        use sgx_isa::Miscselect;

        use serde::ser::{Serialize, Serializer};
        use serde::de::{Deserialize, Deserializer};

        pub fn serialize<S: Serializer>(flags: &Miscselect, serializer: S) -> Result<S::Ok, S::Error> {
            flags.bits().serialize(serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Miscselect, D::Error> {
            Deserialize::deserialize(deserializer).map(Miscselect::from_bits_truncate)
        }
    }

    pub mod attributes_flags {
        use sgx_isa::AttributesFlags;

        use serde::ser::{Serialize, Serializer};
        use serde::de::{Deserialize, Deserializer};

        pub fn serialize<S: Serializer>(flags: &AttributesFlags, serializer: S) -> Result<S::Ok, S::Error> {
            flags.bits().serialize(serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AttributesFlags, D::Error> {
            Deserialize::deserialize(deserializer).map(AttributesFlags::from_bits_truncate)
        }
    }
}
