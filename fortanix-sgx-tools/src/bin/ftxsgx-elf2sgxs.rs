/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate clap;
extern crate sgx_isa;
extern crate sgxs as sgxs_crate;
extern crate xmas_elf;
#[macro_use]
extern crate failure;

use std::borrow::Borrow;
use std::fs::File;
use std::io::{repeat, Error as IoError, Read};
use std::mem::replace;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use failure::{err_msg, Error, ResultExt};

use xmas_elf::dynamic::{Dynamic as DynEntry, Tag as DynTag};
use xmas_elf::header::Class as HeaderClass;
use xmas_elf::program::{SegmentData, Type as PhType};
use xmas_elf::sections::{SectionData, SHN_UNDEF, ShType};
use xmas_elf::symbol_table::{DynEntry64 as DynSymEntry, Entry};
use xmas_elf::ElfFile;

use sgx_isa::{PageType, SecinfoFlags, Tcs};
use sgxs_crate::sgxs::{self, CanonicalSgxsWriter, SecinfoTruncated, SgxsWrite};
use sgxs_crate::util::{size_fit_natural, size_fit_page};

use clap::ArgMatches;
use std::convert::TryInto;

#[allow(non_snake_case)]
struct Symbols<'a> {
    sgx_entry: &'a DynSymEntry,
    HEAP_BASE: &'a DynSymEntry,
    HEAP_SIZE: &'a DynSymEntry,
    UNMAPPED_BASE: &'a DynSymEntry,
    UNMAPPED_SIZE: &'a DynSymEntry,
    RELA: &'a DynSymEntry,
    RELACOUNT: &'a DynSymEntry,
    ENCLAVE_SIZE: &'a DynSymEntry,
    CFGDATA_BASE: &'a DynSymEntry,
    DEBUG: &'a DynSymEntry,
    EH_FRM_HDR_BASE: Option<&'a DynSymEntry>,
    EH_FRM_HDR_SIZE: Option<&'a DynSymEntry>,
    TEXT_BASE: &'a DynSymEntry,
    TEXT_SIZE: &'a DynSymEntry,
    EH_FRM_OFFSET: Option<&'a DynSymEntry>,
    EH_FRM_LEN: Option<&'a DynSymEntry>,
    EH_FRM_HDR_OFFSET: Option<&'a DynSymEntry>,
    EH_FRM_HDR_LEN: Option<&'a DynSymEntry>,
}
struct SectionRange {
    offset: u64,
    size: u64,
}

struct Dynamic<'a> {
    rela: &'a DynEntry<u64>,
    relacount: &'a DynEntry<u64>,
}

struct Splice {
    address: u64,
    value: Vec<u8>,
    /// Remove the splice if it is at the end of a segment
    truncate: bool,
}

impl PartialEq for Splice {
    fn eq(&self, other: &Self) -> bool {
        self.address.eq(&other.address)
    }
}
impl Eq for Splice {}
impl PartialOrd for Splice {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}
impl Ord for Splice {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}
impl Splice {
    fn for_sym_u64(address: &DynSymEntry, value: u64) -> Splice {
        Splice {
            address: address.value(),
            value: value.to_le_bytes().to_vec(),
            truncate: false,
        }
    }

    fn for_sym_u8(address: &DynSymEntry, value: u8) -> Splice {
        Splice {
            address: address.value(),
            value: vec![value],
            truncate: false,
        }
    }
}

pub struct LayoutInfo<'a> {
    elf: ElfFile<'a>,
    sym: Symbols<'a>,
    dynamic: Option<Dynamic<'a>>,
    ssaframesize: u32,
    heap_size: u64,
    stack_size: u64,
    unmapped_size: u64,
    threads: usize,
    debug: bool,
    library: bool,
    sized: bool,
    ehfrm: SectionRange,
    ehfrm_hdr: SectionRange,
    text: SectionRange,
}

macro_rules! read_syms {
    (mandatory: $($mandatory_name:ident),* optional: $($optional_name:ident),* in $syms:ident : $elf:ident) => {{
        $(let mut $mandatory_name=None;)*
        $(let mut $optional_name=None;)*
        for sym in $syms.iter().skip(1) {
            if sym.shndx()==SHN_UNDEF {
                bail!("Found undefined dynamic symbol: {}", sym.get_name(&$elf).map_err(err_msg)?);
            } $(else if sym.get_name(&$elf).map_err(err_msg)?==stringify!($mandatory_name) {
                if replace(&mut $mandatory_name,Some(sym)).is_some() {
                    bail!("Found symbol twice: {}", stringify!($mandatory_name));
                }
            })*
            $(else if sym.get_name(&$elf).map_err(err_msg)?==stringify!($optional_name) {
                if replace(&mut $optional_name,Some(sym)).is_some() {
                    bail!("Found symbol twice: {}", stringify!($optional_name));
                }
            })*
        }
        if let ($(Some($mandatory_name)),*)=($($mandatory_name),*) {
            Symbols{$($mandatory_name:$mandatory_name),*,
                    $($optional_name:$optional_name),*}
        } else {
            let mut missing = String::new();
            $(if $mandatory_name.is_none() {
                if !missing.is_empty() {
                    missing += ", ";
                }
                missing += stringify!($mandatory_name);
            })*
            bail!("These dynamic symbols are missing: {}", missing)
        }
    }}
}

macro_rules! check_size {
    ($syms:ident.$name:ident == $size:expr) => {{
        let size = $syms.$name.size();
        if size != $size {
            bail!(
                "Dynamic symbol {} doesn't have the right size. Expected size {}, got {}.",
                stringify!($name),
                $size,
                size
            );
        }
    }};
    ($name:ident == $size:expr) => {{
        let size = $name.size();
        if size != $size {
            bail!(
                "Dynamic symbol {} doesn't have the right size. Expected size {}, got {}.",
                stringify!($name),
                $size,
                size
            );
        }
    }};
}

impl<'a> LayoutInfo<'a> {
    // Check version defined in rust-lang assembly code is supported, see .note.x86_64-fortanix-unknown-sgx section in https://github.com/rust-lang/rust/blob/master/src/libstd/sys/sgx/abi/entry.S
    fn check_toolchain_version(elf: &ElfFile<'a>) -> Result<(), Error> {
        let note_header = elf.find_section_by_name(".note.x86_64-fortanix-unknown-sgx")
            .ok_or_else(|| format_err!("Could not find .note.x86_64-fortanix-unknown-sgx header!"))?;

        if note_header.get_type() != Ok(ShType::Note) {
            bail!("Invalid type {:?} for section: .note.x86_64-fortanix-unknown-sgx", note_header.get_type());
        }

        match note_header.get_data(&elf) {
            Ok(SectionData::Note64(header, ptr)) => {
                if header.name(ptr) != "toolchain-version" {
                    bail!("Expecting 'toolchain-version' as name for .note.x86_64-fortanix-unknown-sgx");
                }

                let desc = header.desc(ptr);
                
                // According to entry.S in rust-lang 'desc - toolchain version number, 32-bit LE'
                let version = u32::from_le_bytes(desc.try_into()
                    .map_err(|_| format_err!("Expecting 32 bit 'toolchain-version' in .note.x86_64-fortanix-unknown-sgx"))?);

                const MAX_SUPPORTED_VERSION: u32 = 1;
                
                if version > MAX_SUPPORTED_VERSION {
                    bail!("Update required for 'fortanix-sgx-tools'. ELF file has toolchain version {}, installed tools supports up to version {}", version, MAX_SUPPORTED_VERSION);
                }
            },
            Ok(_) => bail!("Section data for .note.x86_64-fortanix-unknown-sgx is not a note."),
            Err(_) => bail!("Failed fetching data for section .note.x86_64-fortanix-unknown-sgx.")
        }

        Ok(())
    }
    
    #[allow(non_snake_case)]
    fn check_symbols(elf: &ElfFile<'a>) -> Result<Symbols<'a>, Error> {
        let dynsym = elf
            .find_section_by_name(".dynsym")
            .ok_or_else(|| format_err!("Could not find dynamic symbol table!"))?;

        let syms =
            if let SectionData::DynSymbolTable64(syms) = dynsym.get_data(&elf).map_err(err_msg)? {
                syms
            } else {
                bail!(".dynsym section is not a dynamic symbol table!");
            };

        // Optional symbols used for compatibility. Old versions use 'EH_FRM_HDR_BASE, EH_FRM_HDR_SIZE', new versions use 'EH_FRM_OFFSET, EH_FRM_LEN, EH_FRM_HDR_OFFSET, EH_FRM_HDR_LEN.
        // Tool must support both variants for backwards compatibility at least until 'https://github.com/fortanix/rust-sgx/issues/174' is merged into rust-lang.
        //
        // Variables have been renamed due to missing 'toolchain' version checks. Rename will cause compile-time failure if using old tool with new toolchain assembly code.
        let syms = read_syms!(mandatory: sgx_entry, HEAP_BASE, HEAP_SIZE, RELA, RELACOUNT, ENCLAVE_SIZE, CFGDATA_BASE, DEBUG, TEXT_BASE, TEXT_SIZE, UNMAPPED_BASE, UNMAPPED_SIZE
                              optional: EH_FRM_HDR_BASE, EH_FRM_HDR_SIZE, EH_FRM_OFFSET, EH_FRM_LEN, EH_FRM_HDR_OFFSET, EH_FRM_HDR_LEN
                              in syms : elf);


        check_size!(syms.HEAP_BASE == 8);
        check_size!(syms.HEAP_SIZE == 8);
        check_size!(syms.UNMAPPED_BASE == 8);
        check_size!(syms.UNMAPPED_SIZE == 8);
        check_size!(syms.RELA == 8);
        check_size!(syms.RELACOUNT == 8);
        check_size!(syms.ENCLAVE_SIZE == 8);
        check_size!(syms.CFGDATA_BASE == 8);
        check_size!(syms.DEBUG == 1);
        check_size!(syms.TEXT_BASE == 8);
        check_size!(syms.TEXT_SIZE == 8);

        if (syms.ENCLAVE_SIZE.value() & (syms.ENCLAVE_SIZE.size() - 1)) != 0 {
            // ENCLAVE_SIZE should be naturally aligned such that `sgxs-append`
            // can easily fill in the value.
            bail!("ENCLAVE_SIZE symbol is not naturally aligned")
        }

        if let (Some(EH_FRM_HDR_BASE), Some(EH_FRM_HDR_SIZE)) = (syms.EH_FRM_HDR_BASE, syms.EH_FRM_HDR_SIZE) {
            check_size!(EH_FRM_HDR_BASE == 8);
            check_size!(EH_FRM_HDR_SIZE == 8);
        } else if let (Some(EH_FRM_OFFSET), Some(EH_FRM_LEN), Some(EH_FRM_HDR_OFFSET), Some(EH_FRM_HDR_LEN)) = (syms.EH_FRM_OFFSET, syms.EH_FRM_LEN, syms.EH_FRM_HDR_OFFSET, syms.EH_FRM_HDR_LEN) {
            check_size!(EH_FRM_OFFSET == 8);
            check_size!(EH_FRM_LEN == 8);
            check_size!(EH_FRM_HDR_OFFSET == 8);
            check_size!(EH_FRM_HDR_LEN == 8);
        } else {
            bail!("Missing EH Frame header symbols, application must either have (EH_FRM_HDR_BASE/EH_FRM_HDR_SIZE) or (EH_FRM_OFFSET, EH_FRM_LEN, EH_FRM_HDR_OFFSET, EH_FRM_HDR_LEN");
        }
        
        Ok(syms)
    }

    fn check_section(elf: &ElfFile<'a>, section_name: &str) -> Result<SectionRange, Error> {
        let sec = elf
            .find_section_by_name(&section_name)
            .ok_or_else(|| format_err!("Could not find {}!", section_name))?;
        Ok(SectionRange {
            offset: sec.address(),
            size: sec.size(),
        })
    }

    fn check_dynamic(elf: &ElfFile<'a>) -> Result<Option<Dynamic<'a>>, Error> {
        use xmas_elf::dynamic::Tag::*;
        const DT_RELACOUNT: DynTag<u64> = OsSpecific(0x6ffffff9);
        const DT_RELCOUNT: DynTag<u64> = OsSpecific(0x6ffffffa);
        //const DT_PLTPADSZ: DynTag<u64> = OsSpecific(0x6ffffdf9);
        //const DT_PLTPAD: DynTag<u64> = OsSpecific(0x6ffffefd);

        let dynh = elf
            .program_iter()
            .find(|ph| ph.get_type() == Ok(PhType::Dynamic))
            .ok_or_else(|| format_err!("Could not found dynamic section!"))?;

        let dyns = if let SegmentData::Dynamic64(dyns) = dynh.get_data(&elf).map_err(err_msg)? {
            dyns
        } else {
            bail!("PT_DYNAMIC segment is not a dynamic section!")
        };

        let mut rela = None;
        let mut relacount = None;

        for dynamic in dyns {
            match dynamic.get_tag().map_err(err_msg)? {
                // Some entries for PLT/GOT checking are currently
                // commented out. I *think* that if there were an actual
                // PLT/GOT problem, that would be caught by the remaining
                // entries or check_relocs().
                PltRelSize | PltRel | JmpRel /*| Pltgot | DT_PLTPADSZ | DT_PLTPAD*/ =>
                    bail!("Unsupported dynamic entry: PLT/GOT"),
                Init | InitArray | InitArraySize =>
                    bail!("Unsupported dynamic entry: .init functions"),
                Fini | FiniArray | FiniArraySize =>
                    bail!("Unsupported dynamic entry: .fini functions"),
                Rel | RelSize | RelEnt | DT_RELCOUNT =>
                    bail!("Unsupported dynamic entry: relocations with implicit addend"),
                Rela => if replace(&mut rela, Some(dynamic)).is_some() {
                    bail!("Found dynamic entry twice: DT_RELA")
                },
                DT_RELACOUNT => if replace(&mut relacount, Some(dynamic)).is_some() {
                    bail!("Found dynamic entry twice: DT_RELACOUNT")
                },
                _ => {}
            }
        }

        match (rela, relacount) {
            (Some(rela), Some(relacount)) => Ok(Some(Dynamic { rela, relacount })),
            (None, None) => Ok(None),
            (_, None) => bail!("DT_RELA found, but DT_RELACOUNT not found"),
            (None, _) => bail!("DT_RELACOUNT found, but DT_RELA not found"),
        }
    }

    fn check_relocs(elf: &ElfFile<'a>, dynamic: Option<&Dynamic<'a>>) -> Result<(), Error> {
        const R_X86_64_RELATIVE: u32 = 8;

        let writable_ranges = elf
            .program_iter()
            .filter_map(|ph| {
                if ph.get_type() == Ok(PhType::Load) && ph.flags().is_write() {
                    Some(ph.virtual_addr()..(ph.virtual_addr() + ph.mem_size()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut count = 0;
        for section in elf.section_iter() {
            if let SectionData::Rela64(relas) = section.get_data(&elf).map_err(err_msg)? {
                count += relas.len();
                for rela in relas {
                    let shind = rela.get_symbol_table_index();
                    let rtype = rela.get_type();
                    if (shind, rtype) != (0, R_X86_64_RELATIVE) {
                        bail!("Invalid relocation: section={} type={}", shind, rtype);
                    }
                    let offset = rela.get_offset();
                    if writable_ranges
                        .iter()
                        .find(|r| offset >= r.start && (offset + 8) <= r.end)
                        .is_none()
                    {
                        bail!(
                            "Relocation at 0x{:016x} outside of writable segments",
                            offset
                        );
                    }
                }
            }
        }

        let target = dynamic
            .and_then(|d| d.relacount.get_val().ok())
            .unwrap_or(0);
        if count as u64 != target {
            bail!("Expected {} relocations, found {}", target, count);
        }

        Ok(())
    }

    pub fn new(
        elf: ElfFile<'a>,
        ssaframesize: u32,
        heap_size: u64,
        stack_size: u64,
        unmapped_size: u64,
        threads: usize,
        debug: bool,
        library: bool,
        sized: bool,
    ) -> Result<LayoutInfo<'a>, Error> {
        if let HeaderClass::SixtyFour = elf.header.pt1.class() {
        } else {
            bail!("Only 64-bit ELF supported!");
        }
        Self::check_toolchain_version(&elf)?;
        let sym = Self::check_symbols(&elf)?;
        let dynamic = Self::check_dynamic(&elf)?;
        Self::check_relocs(&elf, dynamic.as_ref())?;
        let ehfrm = Self::check_section(&elf, ".eh_frame")?;
        let ehfrm_hdr = Self::check_section(&elf, ".eh_frame_hdr")?;
        let text = Self::check_section(&elf, ".text")?;

        Ok(LayoutInfo {
            elf,
            sym,
            dynamic,
            ssaframesize,
            heap_size,
            stack_size,
            unmapped_size,
            threads,
            debug,
            library,
            ehfrm,
            ehfrm_hdr,
            text,
            sized,
        })
    }

    #[allow(non_snake_case)]
    pub fn write_elf_segments<W: SgxsWrite>(
        &self,
        writer: &mut CanonicalSgxsWriter<W>,
        heap_addr: u64,
        unmapped_addr: u64,
        memory_size: u64,
        enclave_size: Option<u64>,
    ) -> Result<(), Error> {
        let mut splices = vec![
            Splice::for_sym_u64(self.sym.HEAP_BASE, heap_addr),
            Splice::for_sym_u64(self.sym.HEAP_SIZE, self.heap_size),
            Splice::for_sym_u64(self.sym.UNMAPPED_BASE, unmapped_addr),
            Splice::for_sym_u64(self.sym.UNMAPPED_SIZE, self.unmapped_size),
            Splice::for_sym_u64(
                self.sym.RELA,               
                self.dynamic
                    .as_ref()
                    .and_then(|d| d.rela.get_ptr().ok())
                    .unwrap_or(0),
                
            ),
            Splice::for_sym_u64(
                self.sym.RELACOUNT,
                self.dynamic
                    .as_ref()
                    .and_then(|d| d.relacount.get_val().ok())
                    .unwrap_or(0),
            ),
            Splice::for_sym_u64(self.sym.CFGDATA_BASE, memory_size),
            Splice::for_sym_u8(self.sym.DEBUG, self.debug as _),
            Splice::for_sym_u64(self.sym.TEXT_BASE, self.text.offset),
            Splice::for_sym_u64(self.sym.TEXT_SIZE, self.text.size),
        ];

        if let (Some(EH_FRM_HDR_BASE), Some(EH_FRM_HDR_SIZE)) = (self.sym.EH_FRM_HDR_BASE, self.sym.EH_FRM_HDR_SIZE) {
            splices.push(Splice::for_sym_u64(EH_FRM_HDR_BASE, self.ehfrm_hdr.offset));
            splices.push(Splice::for_sym_u64(EH_FRM_HDR_SIZE, self.ehfrm_hdr.size));
        }
        else if let (Some(EH_FRM_OFFSET), Some(EH_FRM_LEN), Some(EH_FRM_HDR_OFFSET), Some(EH_FRM_HDR_LEN)) = (self.sym.EH_FRM_OFFSET, self.sym.EH_FRM_LEN, self.sym.EH_FRM_HDR_OFFSET, self.sym.EH_FRM_HDR_LEN) {
            splices.push(Splice::for_sym_u64(EH_FRM_OFFSET, self.ehfrm.offset));
            splices.push(Splice::for_sym_u64(EH_FRM_LEN, self.ehfrm.size));
            splices.push(Splice::for_sym_u64(EH_FRM_HDR_OFFSET, self.ehfrm_hdr.offset));
            splices.push(Splice::for_sym_u64(EH_FRM_HDR_LEN, self.ehfrm_hdr.size));
        }
        else {
            bail!("Missing .eh_frame header symbols, application must have symbols exported by rust x86_64_fortanix_unknown_sgx toolchain, either (EH_FRM_HDR_BASE/EH_FRM_HDR_SIZE) or (EH_FRM_OFFSET, EH_FRM_LEN, EH_FRM_HDR_OFFSET, EH_FRM_HDR_LEN");
        }

        if let Some(enclave_size) = enclave_size {
            splices.push(Splice::for_sym_u64(self.sym.ENCLAVE_SIZE, enclave_size));
        }
        if let Some(sec_no_sgx) = self.elf.find_section_by_name(".text_no_sgx") {
            // Overwrite .text_no_sgx section with NOPs
            splices.push(Splice {
                address: sec_no_sgx.address(),
                value: vec![0x90; sec_no_sgx.size() as usize],
                truncate: true, /* try to remove if at end of segment */
            });
        }

        splices.sort(); // `Splice` sorts by address
        let mut cur_splice = splices.iter().peekable();

        for ph in self
            .elf
            .program_iter()
            .filter(|ph| ph.get_type() == Ok(PhType::Load))
        {
            let mut secinfo = SecinfoTruncated {
                flags: PageType::Reg.into(),
            };
            if ph.flags().is_read() {
                secinfo.flags.insert(SecinfoFlags::R);
            }
            if ph.flags().is_write() {
                secinfo.flags.insert(SecinfoFlags::W);
            }
            if ph.flags().is_execute() {
                secinfo.flags.insert(SecinfoFlags::X);
            }
            let start = ph.virtual_addr();
            let base = start & !0xfff;
            let mut end = start + ph.mem_size();
            let base_data;
            if let SegmentData::Undefined(data) = ph.get_data(&self.elf).map_err(err_msg)? {
                base_data = data;
            } else {
                // Reachable if xmas-elf changes definition of SegmentData
                unreachable!();
            }

            // To defend against LVI attacks, the first page of an enclave should not be executable.
            // https://software.intel.com/security-software-guidance/insights/deep-dive-load-value-injection#adhocLBmitigation
            if base == 0 && ph.flags().is_execute() {
                bail!("First page of the enclave should not be executable");
            }

            let mut data: Box<dyn Read>;
            let mut cur_ptr = base;

            if cur_ptr == start {
                data = Box::new(base_data);
            } else {
                data = Box::new(repeat(0).take(start - cur_ptr).chain(&base_data[..]));
            }

            while cur_splice
                .peek()
                .map_or(false, |s| s.address >= base && (s.address + (s.value.len() as u64)) <= end)
            {
                let splice = cur_splice.next().unwrap();

                let nd = data.take(splice.address - base); /* add data up to the splice */
                
                cur_ptr = splice.address + (splice.value.len() as u64);
                if splice.truncate && cur_ptr == end {
                    end = splice.address;
                    data = Box::new(nd);
                } else {
                    let nd = nd.chain(&splice.value[..]); /* add splice value */
                
                    if cur_ptr < start {
                        data =
                            Box::new(nd.chain(repeat(0).take(start - cur_ptr).chain(&base_data[..])));
                    } else {
                        data = Box::new(nd.chain(&base_data[(cur_ptr - start) as usize..]));
                    }
                }
            }

            writer.write_pages(
                Some(&mut data),
                (size_fit_page(end - base) / 0x1000) as usize,
                Some(base),
                secinfo
            )?
        }

        Ok(())
    }

    pub fn write<W: SgxsWrite>(&self, writer: &mut W) -> Result<(), Error> {
        let max_addr = self
            .elf
            .program_iter()
            .filter_map(|ph| {
                if ph.get_type() == Ok(PhType::Load) {
                    Some(ph.virtual_addr() + ph.mem_size())
                } else {
                    None
                }
            })
            .max()
            .ok_or_else(|| format_err!("No loadable segments found"))?;

        let heap_addr = size_fit_page(max_addr);
        let unmapped_addr = size_fit_page(heap_addr + self.heap_size);
        let mut thread_start = size_fit_page(unmapped_addr + self.unmapped_size);
        const THREAD_GUARD_SIZE: u64 = 0x10000;
        const TLS_SIZE: u64 = 0x1000;
        let nssa = 1u32;
        let thread_size = THREAD_GUARD_SIZE
            + self.stack_size
            + TLS_SIZE
            + (1 + (nssa as u64) * (self.ssaframesize as u64)) * 0x1000;
        let memory_size = thread_start + (self.threads as u64) * thread_size;
        let enclave_size = if self.sized {
            Some(size_fit_natural(memory_size))
        } else {
            None
        };

        let mut writer = CanonicalSgxsWriter::new(
            writer,
            sgxs::MeasECreate {
                size: enclave_size.unwrap_or_else(|| self.sym.ENCLAVE_SIZE.value()),
                ssaframesize: self.ssaframesize,
            },
            self.sized,
        )?;

        // Output ELF sections
        self.write_elf_segments(&mut writer, heap_addr, unmapped_addr, memory_size, enclave_size)?;

        // Output heap
        let secinfo = SecinfoTruncated {
            flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
        };
        writer.write_pages::<&[u8]>(
            None,
            (self.heap_size as usize) / 0x1000,
            Some(heap_addr),
            secinfo
        )?;

        for i in 0..self.threads {
            let stack_addr = thread_start + THREAD_GUARD_SIZE;
            let stack_tos = stack_addr + self.stack_size;
            let tls_addr = stack_tos;
            let tcs_addr = tls_addr + TLS_SIZE;

            // Output stack
            let secinfo = SecinfoTruncated {
                flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
            };
            writer.write_pages::<&[u8]>(
                None,
                (self.stack_size as usize) / 0x1000,
                Some(stack_addr),
                secinfo
            )?;

            // Output TLS
            let secondary = match (self.library, i) {
                (true, _) | (false, 0) => false,
                (false, _) => true,
            };
            let tls = unsafe {
                std::mem::transmute::<_, [u8; 32]>([stack_tos, secondary as u64, 0u64, 0u64])
            };
            let secinfo = SecinfoTruncated {
                flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
            };
            writer.write_pages(Some(&mut &tls[..]), 1, Some(tls_addr), secinfo)?;

            // Output TCS, SSA
            let tcs = Tcs {
                ossa: tcs_addr + 0x1000,
                nssa: nssa,
                oentry: self.sym.sgx_entry.value(),
                ofsbasgx: tls_addr,
                ogsbasgx: stack_tos,
                fslimit: 0xfff,
                gslimit: 0xfff,
                ..Tcs::default()
            };
            let tcs = unsafe { std::mem::transmute::<_, [u8; 4096]>(tcs) };
            let secinfo = SecinfoTruncated {
                flags: PageType::Tcs.into(),
            };
            writer.write_page(Some(&mut &tcs[..]), Some(tcs_addr), secinfo)?;
            let secinfo = SecinfoTruncated {
                flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
            };
            writer.write_pages::<&[u8]>(
                None,
                (nssa * self.ssaframesize) as usize,
                None,
                secinfo
            )?;

            thread_start += thread_size;
        }

        Ok(())
    }
}

/////////////////
// Driver code //
/////////////////

trait NumArg: Copy {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;

    fn parse_arg<S: Borrow<str>>(s: S) -> Self {
        parse_num(s).unwrap()
    }

    fn validate_arg(s: String) -> Result<(), String> {
        match parse_num::<Self, _>(s) {
            Ok(_) => Ok(()),
            Err(_) => Err(String::from("the value must be numeric")),
        }
    }
}

fn parse_num<T: NumArg, S: Borrow<str>>(s: S) -> Result<T, ParseIntError> {
    let s = s.borrow();
    if s.starts_with("0x") {
        T::from_str_radix(&s[2..], 16)
    } else {
        T::from_str_radix(s, 10)
    }
}

macro_rules! impl_numarg(
($($t:ty),+) => ($(
    impl NumArg for $t {
        fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
            Self::from_str_radix(src,radix)
        }
    }
)+););
impl_numarg!(u32, u64, usize);

fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, IoError> {
    let mut f = File::open(path)?;
    let mut buf = vec![];
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn main_result(args: ArgMatches) -> Result<(), Error> {
    let ssaframesize = u32::parse_arg(args.value_of("ssaframesize").unwrap());
    let heap_size = u64::parse_arg(args.value_of("heap-size").unwrap());
    let stack_size = u64::parse_arg(args.value_of("stack-size").unwrap());
    let threads = usize::parse_arg(args.value_of("threads").unwrap());
    let unmapped_size = u64::parse_arg(args.value_of("unmapped-memory-size").unwrap());

    let debug = args.is_present("debug");
    let library = args.is_present("library");
    if library {
        println!("WARNING: Library support is experimental");
    }
    let sized = !args.is_present("unsized");
    let srclib = PathBuf::from(args.value_of("elf").unwrap());
    let srcbuf = read_file(&srclib).context("Reading ELF file")?;
    let srcelf = ElfFile::new(&srcbuf).map_err(|s| format_err!("Loading ELF file: {}", s))?;
    let layout = LayoutInfo::new(
        srcelf,
        ssaframesize,
        heap_size,
        stack_size,
        unmapped_size,
        threads,
        debug,
        library,
        sized,
    )?;

    let mut outfile = args
        .value_of("output")
        .map(|out| File::create(out))
        .unwrap_or_else(|| File::create(srclib.with_extension("sgxs")))
        .unwrap();
    layout.write(&mut outfile)?;

    Ok(())
}

fn main() {
    use clap::{App, AppSettings, Arg};

    let args = App::new("ftxsgx-elf2sgxs")
        .about("Convert an x86_64-fortanix-unknown-sgx ELF binary to SGXS")
        .version(crate_version!())
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(
            Arg::with_name("ssaframesize")
                .long("ssaframesize")
                .value_name("PAGES")
                .validator(u32::validate_arg)
                .default_value("1")
                .help("Specify SSAFRAMESIZE"),
        )
        .arg(
            Arg::with_name("threads")
                .short("t")
                .long("threads")
                .value_name("N")
                .validator(usize::validate_arg)
                .default_value("1")
                .help("Specify the number of threads"),
        )
        .arg(
            Arg::with_name("heap-size")
                .short("H")
                .long("heap-size")
                .value_name("BYTES")
                .validator(u64::validate_arg)
                .required(true)
                .help("Specify heap size"),
        )
        .arg(
            Arg::with_name("stack-size")
                .short("S")
                .long("stack-size")
                .value_name("BYTES")
                .validator(u64::validate_arg)
                .required(true)
                .help("Specify stack size"),
        )
        .arg(
            Arg::with_name("unmapped-memory-size")
                .short("U")
                .long("unmapped-memory-size")
                .value_name("BYTES")
                .validator(u64::validate_arg)
                .required(false)
                .default_value("0")
                .help("Specify the (minimum) size of unmapped memory (useable on SGXv2 capable processors only)"),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("Set enclave debug mode"),
        )
        .arg(
            Arg::with_name("library")
                .long("library")
                .help("This is a library enclave (experimental)"),
        )
        .arg(
            Arg::with_name("unsized")
                .long("unsized")
                .help("Output an unsized enclave, for use with sgxs-append"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Specify output file"),
        )
        .arg(
            Arg::with_name("elf")
                .index(1)
                .required(true)
                .help("Path to the ELF binary to be converted"),
        )
        .get_matches();

    if let Err(e) = main_result(args) {
        println!("ERROR: {}", e);
        std::process::exit(1);
    };
}
