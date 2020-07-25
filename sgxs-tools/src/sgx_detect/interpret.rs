//! Interpreting raw values returned from the environment

use std::arch::x86_64::CpuidResult;
use std::convert::From;

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use failure::Error;
use sgx_isa::{AttributesFlags, Miscselect};

#[cfg(windows)]
extern crate winapi;

#[cfg(windows)]
#[path = "imp/windows.rs"]
mod imp;
#[cfg(unix)]
#[path = "imp/linux.rs"]
mod imp;

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

pub trait EfiVariable where Self: std::marker::Sized {

    // EFI variable attributes value bitmask constants
    const NON_VOLATILE: u32 = 0x00000001;
    const BOOTSERVICE_ACCESS: u32 = 0x00000002;
    const RUNTIME_ACCESS: u32 = 0x00000003;
    const HARDWARE_ERROR_RECORD: u32 = 0x00000004;
    const AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000010;
    const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;
    const APPEND_WRITE: u32 = 0x00000040;
    // This option is not available in windows
    const ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x00000080;

    const NAME: &'static str = "INVALID_EFI_VARIABLE";
    const GUID: &'static str = "00000000-0000-0000-0000-000000000000";

    fn read_from_env(&mut self) -> Result<(), Error>;
    fn write_to_env(&self) -> Result<(), Error>;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EfiEpcbios {
    pub attributes: u32,
    pub prm_bins: u32,
    pub max_epc_size: u32,
    pub current_epc_size: u32,
    pub epc_map: [u32; 32],
}

impl Default for EfiEpcbios {
    fn default() -> Self {
        EfiEpcbios {
            attributes: 0,
            prm_bins: 0,
            max_epc_size: 0,
            current_epc_size: 0,
            epc_map: [0; 32],
        }
    }
}

impl EfiVariable for EfiEpcbios {
    const NAME: &'static str = "EPCBIOS";
    const GUID: &'static str = "c60aa7f6-e8d6-4956-8ba1-fe26298f5e87";

    fn read_from_env(&mut self) -> Result<(), Error> {
        let (v, attr) = imp::read_efi_var(EfiEpcbios::NAME, EfiEpcbios::GUID)?;
        if v.len() != std::mem::size_of::<Self>() - 4 { // Subtracting size of attributes
            warn!("Invalid size for EPCBIOS EFI variable: {}", v.len());
        }
        let mut v = &v[..];

        self.attributes = attr;
        self.prm_bins = v.read_u32::<LE>()?;
        self.max_epc_size = v.read_u32::<LE>()?;
        self.current_epc_size = v.read_u32::<LE>()?;
        self.epc_map = {
            let mut map = [0u32; 32];
            for elem in &mut map {
                *elem = v.read_u32::<LE>()?;
            }
            map
        };

        Ok(())
    }

    fn write_to_env(&self) -> Result<(), Error> {
        if self.attributes == 0 {
            // Set the correct attributes here
        }

        let mut v = Vec::new();
        v.write_u32::<LE>(self.prm_bins)?;
        v.write_u32::<LE>(self.max_epc_size)?;
        v.write_u32::<LE>(self.current_epc_size)?;
        for elem in self.epc_map.iter() {
            v.write_u32::<LE>(*elem)?;
        }

        imp::write_efi_var(EfiEpcbios::NAME, EfiEpcbios::GUID, v, self.attributes)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EfiEpcsw {
    pub attributes: u32,
    pub epc_size: u32,
}

impl Default for EfiEpcsw {
    fn default() -> Self {
        EfiEpcsw {
            attributes: 0,
            epc_size: 0,
        }
    }
}


impl EfiVariable for EfiEpcsw {
    const NAME: &'static str = "EPCSW";
    const GUID: &'static str = "d69a279b-58eb-45d1-a148-771bb9eb5251";

    fn read_from_env(&mut self) -> Result<(), Error> {
        let (v, attr) = imp::read_efi_var(EfiEpcsw::NAME, EfiEpcsw::GUID)?;
        if v.len() != std::mem::size_of::<Self>() - 4 { // Subtracting size of attributes
            warn!("Invalid size for EPCSW EFI variable: {}", v.len());
        }
        let mut v = &v[..];

        self.attributes = attr;
        self.epc_size = v.read_u32::<LE>()?;

        Ok(())
    }

    fn write_to_env(&self) -> Result<(), Error> {
        if self.attributes == 0 {
            // Set the correct attributes here
        }

        let mut v = Vec::new();

        v.write_u32::<LE>(self.epc_size)?;

        imp::write_efi_var(EfiEpcsw::NAME, EfiEpcsw::GUID, v, self.attributes)?;
        Ok(())
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
    pub attributes: u32,
    pub status: SgxEnableStatus,
}

impl Default for EfiSoftwareguardstatus {
    fn default() -> Self {
        EfiSoftwareguardstatus{
            attributes: 0,
            status: SgxEnableStatus::Unknown,
        }
    }
}

impl EfiVariable for EfiSoftwareguardstatus {
    const NAME: &'static str = "SOFTWAREGUARDSTATUS";
    const GUID: &'static str = "9cb2e73f-7325-40f4-a484-659bb344c3cd";

    fn read_from_env(&mut self) -> Result<(), Error> {
        let (v, attr) = imp::read_efi_var(EfiSoftwareguardstatus::NAME, EfiSoftwareguardstatus::GUID)?;
        if v.len() != std::mem::size_of::<Self>() - 4 { // Subtracting size of attributes
            warn!(
                "Invalid size for SOFTWAREGUARDSTATUS EFI variable: {}",
                v.len()
            );
        }
        let status = v.get(0).map(|v| v & 0b11);
        let reserved = v.get(0).map(|v| v & !0b11);

        self.attributes = attr;
        self.status = match status {
            Some(0) => SgxEnableStatus::Disabled,
            Some(1) => SgxEnableStatus::Enabled,
            Some(2) => SgxEnableStatus::SoftwareControlled,
            Some(v) => {
                warn!("EFI variable SOFTWAREGUARDSTATUS: invalid status {:x}", v);
                SgxEnableStatus::Unknown
            }
            None => SgxEnableStatus::Unknown,
        };

        match reserved {
            None | Some(0) => {}
            Some(v) => warn!(
                "EFI variable SOFTWAREGUARDSTATUS: invalid reserved bits: {:x}",
                v
            ),
        }

        Ok(())
    }

    fn write_to_env(&self) -> Result<(), Error> {
        if self.attributes == 0 {
            // Set the correct attributes here
        }

        let mut v = Vec::new();

        v.write_u32::<LE>(self.status as u32)?;

        imp::write_efi_var(EfiSoftwareguardstatus::NAME, EfiSoftwareguardstatus::GUID, v, self.attributes)?;

        Ok(())
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

// sample version String format: "1.7.380"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAgentVersion {
    pub version: String,
}
