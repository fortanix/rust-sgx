/*
 * PE to SGXS converter
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#[macro_use]
extern crate lazy_static;
extern crate sgxs as sgxs_crate;
extern crate pe;
extern crate broadcast;
extern crate sgx_isa;

use std::fs::File;
use std::io::{self,Read,Write};
use std::mem::{transmute,size_of,size_of_val};
use std::collections::HashSet;
use std::sync::atomic;

use broadcast::BroadcastWriter;

use sgxs_crate::crypto::{Sha256Digest,Sha256};
use sgx_isa::{Tcs,Sigstruct,PageType,secinfo_flags,SecinfoFlags};
use sgxs_crate::sgxs::{SgxsWrite,CanonicalSgxsWriter,self,SecinfoTruncated};
use sgxs_crate::util::{size_fit_page,size_fit_natural};

use pe::types::{section_characteristics,SectionHeader,DataDirectory,DirectoryEntry};
use pe::AsOsStr;

//======================
//==== Wire formats ====
//======================

#[allow(dead_code)]
#[repr(packed)]
struct Sgxmeta {
	// next 2 fields: presumably a header signature
	unknown0x635d0e4c: u32,
	unknown0x86a80294: u32,
	unknown0x00000001_1: u32,
	unknown0x00000001_2: u32,
	// the size of this structure
	struct_size: u32,
	// the number of threads to allocate
	threads: u32,
	// Field 8 in TLS section, see below
	tls_field_8: u32,
	tcs_nssa: u32,
	unknown0x00000001_3: u32,
	stack_size: u32,
	heap_size: u32,
	unknown0x00000a48: u32,
	unknown0x00000000: u32,
	requested_attributes: u64,
	// The XFRM attributes that should be enabled, if supported by the platform.
	requested_attributes_xfrm: u64,
	sigstruct: Sigstruct,
}

#[allow(dead_code)]
#[repr(packed)]
struct Tls64 {
	unchanged1: u64,
	// Top-of-stack offset from TCS base
	tos_tcs_offset1: u64,
	// Top-of-stack offset from TCS base
	tos_tcs_offset2: u64,
	// Bottom-of-stack offset from TCS base
	bos_tcs_offset: u64,
	// Save state area (SSA) offset from TCS base
	ssa_tcs_offset: u64,
	// GPRSGX offset in the SSA from TCS base
	gprsgx_tcs_offset: u64,
	// SSA size?
	unknown0x0000000000001000: u64,
	sgxmeta_field_7: u8,
	unchanged2: [u8;7],
	// Heap offset from enclave base
	heap_base_offset: u64,
	enclave_size: u64,
	unchanged3: u64,
	unknown0x0000000000001030: u64,
	unknown0x00000001: u32,
	heap_size: u32,
}

#[allow(dead_code)]
#[repr(packed)]
struct Tls32 {
	unknown0xffffffff: u32,
	// Top-of-stack offset from TCS base
	tos_tcs_offset1: u32,
	// Top-of-stack offset from TCS base
	tos_tcs_offset2: u32,
	// Bottom-of-stack offset from TCS base
	bos_tcs_offset: u32,
	// Save state area (SSA) offset from TCS base
	ssa_tcs_offset: u32,
	// GPRSGX offset in the SSA from TCS base
	gprsgx_tcs_offset: u32,
	// SSA size?
	unknown0x00001000: u32,
	sgxmeta_field_7: u8,
	unchanged2: [u8;3],
	// Heap offset from enclave base
	heap_base_offset: u32,
	enclave_size: u32,
	unchanged3: u32,
	unknown0x00001018: u32,
	unknown0x00000001: u32,
	unchanged4: u32,
	heap_size: u32,
}

impl Tls64 {
	fn read<'a>(from: & mut &[u8], into: &'a mut Vec<u8>) -> &'a mut Self {
		let (tlsh,last)=from.split_at(size_of::<Self>());
		*from=last;
		into.extend(tlsh);
		unsafe{transmute(&mut into[0])}
	}
}

impl Tls32 {
	fn read<'a>(from: & mut &[u8], into: &'a mut Vec<u8>) -> &'a mut Self {
		let (tlsh,last)=from.split_at(size_of::<Self>());
		*from=last;
		into.extend(tlsh);
		unsafe{transmute(&mut into[0])}
	}
}

//=======================
//==== Utility items ====
//=======================

#[derive(Debug)]
enum Error {
	TooManySgxmetaSections,
	TooManyTlsSections,
	NotEnoughSgxmetaSections,
	NotEnoughTlsSections,
	TooSmallSgxmetaSection,
	TooSmallTlsSection,
	InvalidSgxmetaSection,
	MissingEnclaveEntry,
	PeError(pe::Error),
	SgxsError(sgxs::Error),
}
use Error::*;

impl From<pe::Error> for Error {
	fn from(err: pe::Error) -> Error {
		PeError(err)
	}
}

impl From<sgxs::Error> for Error {
	fn from(err: sgxs::Error) -> Error {
		SgxsError(err)
	}
}

type Result<T> = ::std::result::Result<T, Error>;

fn section_to_secinfo_flags(header: &SectionHeader) -> SecinfoFlags {
	let mut flags=SecinfoFlags::empty();
	if header.characteristics.contains(section_characteristics::IMAGE_SCN_MEM_READ) {
		flags.insert(secinfo_flags::R);
	}
	if header.characteristics.contains(section_characteristics::IMAGE_SCN_MEM_WRITE) {
		flags.insert(secinfo_flags::W);
	}
	if header.characteristics.contains(section_characteristics::IMAGE_SCN_MEM_EXECUTE) {
		flags.insert(secinfo_flags::X);
	}
	flags
}

//====================
//==== PE-to-SGXS ====
//====================

enum LayoutSection<'a> {
	PeHeaderSection(PeHeader<'a>),
	RegularPeSection{header:&'a SectionHeader,data:&'a [u8]},
	TlsPeSection{header:&'a SectionHeader,data:&'a [u8]},
	HeapSection{offset:u64},
	TcsSection{offset:u64},
	TlsSection{offset:u64},
	SsaSection{offset:u64},
	StackSection{offset:u64},
}
use LayoutSection::*;

struct LayoutInfo<'a> {
	sgxmeta: &'a Sgxmeta,
	ssaframesize: u32,
	is64bit: bool,
	tls_size: u64,
	heap_offset: u64,
	enclave_size: u64,
	enclave_entry: u64,
	pages_with_relocs: HashSet<u64>,
	layout: Vec<LayoutSection<'a>>,
}

impl<'a> LayoutInfo<'a> {
	pub fn new(pe: &pe::Pe<'a>) -> Result<LayoutInfo<'a>>  {
		let is64bit=if let pe::PeOptionalHeader::Pe32Plus(_)=pe.get_optional_header() { true } else { false };

		// Load PE sections, and identify sgxmeta and .tls sections.
		let mut layout=vec![PeHeaderSection(try!(PeHeader::new(pe)))];
		let mut opt_sgxmeta=None;
		let mut opt_tls=None;
		let tls_minsize=if is64bit { size_of::<Tls64>() } else { size_of::<Tls32>() } as u32;
		let sgxmeta_minsize=size_of::<Sgxmeta>() as u32;
		for section in pe.get_sections() {
			if section.name.as_os_str()=="sgxmeta" {
				if let Some(_)=opt_sgxmeta {
					return Err(TooManySgxmetaSections);
				} else if section.size_of_raw_data<sgxmeta_minsize {
					return Err(TooSmallSgxmetaSection);
				}
				opt_sgxmeta=Some(section);
			} else if section.name.as_os_str()==".tls" {
				if let Some(_)=opt_tls {
					return Err(TooManyTlsSections);
				} else if section.size_of_raw_data<tls_minsize {
					return Err(TooSmallTlsSection);
				}
				opt_tls=Some(section);
				layout.push(TlsPeSection{header:section,data:try!(pe.ref_slice_at(section.virtual_address,section.size_of_raw_data))});
			} else {
				layout.push(RegularPeSection{header:section,data:try!(pe.ref_slice_at(section.virtual_address,section.size_of_raw_data))});
			}
		}
		let (sgxmeta_s,tls_s)=match (opt_sgxmeta,opt_tls) {
			(Some(meta),Some(tls)) => (meta,tls),
			(Some(_),None)  => return Err(NotEnoughSgxmetaSections),
			_ => return Err(NotEnoughTlsSections),
		};

		let sgxmeta=try!(pe.ref_slice_at(sgxmeta_s.virtual_address,sgxmeta_s.size_of_raw_data)).as_ptr();
		let sgxmeta=unsafe{&*(sgxmeta as *const Sgxmeta)};

		if sgxmeta.unknown0x635d0e4c!=0x635d0e4c ||
		   sgxmeta.unknown0x86a80294!=0x86a80294 {
			return Err(InvalidSgxmetaSection);
		}
		if sgxmeta.unknown0x00000001_1!=0x00000001 ||
		   sgxmeta.unknown0x00000001_2!=0x00000001 ||
		   sgxmeta.unknown0x00000001_3!=0x00000001 ||
		   sgxmeta.unknown0x00000a48!=0x00000a48 ||
		   sgxmeta.unknown0x00000000!=0x00000000 {
			UNKNOWN_VALUE_ENCOUNTERED.store(true,atomic::Ordering::Relaxed);
		}

		let tls_size=size_fit_page(tls_s.virtual_size as u64);

		let ssaframesize=1;

		let mut pages_with_relocs=HashSet::new();
		for it in try!(pe.get_relocations()) {
			let (page_rva,_)=try!(it);
			pages_with_relocs.insert((page_rva.get()>>12) as u64);
		}

		let enclave_entry=match try!(pe.get_exports()).lookup_symbol("enclave_entry") {
			Ok(pe::ExportAddress::Export(rva)) => { rva.get() as u64 },
			Err(pe::Error::DirectoryMissing) | Err(pe::Error::SymbolNotFound) |
			Err(pe::Error::ExportNotFound) | Ok(_) => { return Err(Error::MissingEnclaveEntry) },
			Err(e) => { return Err(e.into()) }
		};

		let last_section=match layout.last() {
			Some(&RegularPeSection{header,..}) | Some(&TlsPeSection{header,..}) => header,
			_ => unreachable!()
		};
		let heap_offset=(last_section.virtual_address.get() as u64)+size_fit_page(last_section.virtual_size as u64);

		layout.push(HeapSection{offset:heap_offset});
		let mut cur_offset=heap_offset+size_fit_page(sgxmeta.heap_size as u64)+0x10000;

		for _ in 0..sgxmeta.threads {
			layout.push(TcsSection{offset:cur_offset});
			cur_offset+=0x1000;
			layout.push(TlsSection{offset:cur_offset});
			cur_offset+=tls_size+0x10000;
			layout.push(SsaSection{offset:cur_offset});
			cur_offset+=((sgxmeta.tcs_nssa*ssaframesize) as u64)*0x1000+0x10000;
			layout.push(StackSection{offset:cur_offset});
			cur_offset+=size_fit_page(sgxmeta.stack_size as u64);
		}

		Ok(LayoutInfo{
			sgxmeta:sgxmeta,
			ssaframesize:ssaframesize,
			is64bit:is64bit,
			tls_size:tls_size,
			heap_offset:heap_offset,
			enclave_size:size_fit_natural(cur_offset),
			enclave_entry:enclave_entry,
			pages_with_relocs:pages_with_relocs,
			layout:layout,
		})
	}

	fn write_pe_section<R: Read,W: SgxsWrite>(&self, writer: &mut CanonicalSgxsWriter<W>, mut data: &mut R, offset: u64, size: u64, secinfo: SecinfoTruncated) -> Result<()> {
		let begin_p=offset>>12;
		let end_p=size_fit_page(offset+size)>>12;
		for p in begin_p..end_p {
			let mut secinfo=secinfo.clone();
			if self.pages_with_relocs.contains(&p) {
				secinfo.flags.insert(secinfo_flags::W);
			}
			try!(writer.write_page(Some(&mut data),Some(p<<12),secinfo));
		}
		Ok(())
	}

	pub fn write<W: SgxsWrite>(&self, writer: &mut W) -> Result<()> {
		let mut writer=try!(CanonicalSgxsWriter::new(writer,sgxs::MeasECreate{size:self.enclave_size,ssaframesize:self.ssaframesize},true));
		for section in &self.layout {
			match section {
				&PeHeaderSection(ref header) => {
					let secinfo=SecinfoTruncated{flags:secinfo_flags::R|PageType::Reg.into()};
					let mut header=header.clone();
					let len=header.data.len();
					let mut splice=header.splice();
					try!(writer.write_pages(Some(&mut splice),(size_fit_page(len as u64)/0x1000) as usize,Some(0),secinfo))
				},
				&RegularPeSection{header,mut data} => {
					let secinfo=SecinfoTruncated{flags:section_to_secinfo_flags(header)|PageType::Reg.into()};
					try!(self.write_pe_section(&mut writer,&mut data,header.virtual_address.get() as u64,header.virtual_size as u64,secinfo));
				},
				&TlsPeSection{header,mut data} => {
					let secinfo=SecinfoTruncated{flags:section_to_secinfo_flags(header)|PageType::Reg.into()};
					let mut splice=self.tls_splice(&mut data);
					try!(self.write_pe_section(&mut writer,&mut splice[..].chain(&mut data),header.virtual_address.get() as u64,header.virtual_size as u64,secinfo));
				},
				&HeapSection{offset} => {
					let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
					try!(writer.write_pages::<&[u8]>(None,(size_fit_page(self.sgxmeta.heap_size as u64)/0x1000) as usize,Some(offset),secinfo));
				},
				&TcsSection{offset} => {
					let tcs=Tcs {
						ossa: offset+0x1000+self.tls_size+0x10000,
						nssa: self.sgxmeta.tcs_nssa,
						oentry: self.enclave_entry,
						ofsbasgx: offset+0x1000,
						ogsbasgx: offset+0x1000,
						fslimit: 0xfff,
						gslimit: 0xfff,
						..Tcs::default()
					};
					let tcs=unsafe{transmute::<_,[u8;4096]>(tcs)};
					let secinfo=SecinfoTruncated{flags:PageType::Tcs.into()};
					try!(writer.write_page(Some(&mut &tcs[..]),Some(offset),secinfo));
				},
				&TlsSection{offset} => {
					let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
					try!(writer.write_pages(Some(&mut io::repeat(0)),(self.tls_size/0x1000) as usize,Some(offset),secinfo));
				},
				&SsaSection{offset} => {
					let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
					try!(writer.write_pages(Some(&mut io::repeat(0)),(self.sgxmeta.tcs_nssa*self.ssaframesize) as usize,Some(offset),secinfo));
				},
				&StackSection{offset} => {
					let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
					try!(writer.write_pages(Some(&mut io::repeat(0xcc)),(size_fit_page(self.sgxmeta.stack_size as u64)/0x1000) as usize,Some(offset),secinfo));
				},
			}
		}
		Ok(())
	}

	fn tls_splice(&self, data: &mut &[u8]) -> Vec<u8> {
		let ssa_tcs_offset=0x1000+self.tls_size+0x10000;
		let gprsgx_tcs_offset=ssa_tcs_offset+0xf48;
		let bos_tcs_offset=ssa_tcs_offset+((self.sgxmeta.tcs_nssa*self.ssaframesize) as u64)*0x1000+0x10000;
		let tos_tcs_offset=bos_tcs_offset+size_fit_page(self.sgxmeta.stack_size as u64);
		let sgxmeta_field_7=self.sgxmeta.tls_field_8 as u8;
		let heap_base_offset=self.heap_offset;
		let enclave_size=self.enclave_size;
		let heap_size=size_fit_page(self.sgxmeta.heap_size as u64) as u32;

		let mut buf=Vec::<u8>::new();

		if self.is64bit {
			let tlsh=Tls64::read(data,&mut buf);

			tlsh.tos_tcs_offset1=tos_tcs_offset;
			tlsh.tos_tcs_offset2=tos_tcs_offset;
			tlsh.bos_tcs_offset=bos_tcs_offset;
			tlsh.ssa_tcs_offset=ssa_tcs_offset;
			tlsh.gprsgx_tcs_offset=gprsgx_tcs_offset;
			tlsh.sgxmeta_field_7=sgxmeta_field_7;
			tlsh.heap_base_offset=heap_base_offset;
			tlsh.enclave_size=enclave_size;
			tlsh.heap_size=heap_size;

			tlsh.unknown0x0000000000001000=0x0000000000001000;
			tlsh.unknown0x0000000000001030=0x0000000000001030;
			tlsh.unknown0x00000001=0x00000001;
		} else {
			let tlsh=Tls32::read(data,&mut buf);

			tlsh.tos_tcs_offset1=tos_tcs_offset as u32;
			tlsh.tos_tcs_offset2=tos_tcs_offset as u32;
			tlsh.bos_tcs_offset=bos_tcs_offset as u32;
			tlsh.ssa_tcs_offset=ssa_tcs_offset as u32;
			tlsh.gprsgx_tcs_offset=gprsgx_tcs_offset as u32;
			tlsh.sgxmeta_field_7=sgxmeta_field_7;
			tlsh.heap_base_offset=heap_base_offset as u32;
			tlsh.enclave_size=enclave_size as u32;
			tlsh.heap_size=heap_size;

			tlsh.unknown0xffffffff=0xffffffff;
			tlsh.unknown0x00001000=0x00001000;
			tlsh.unknown0x00001018=0x00001018;
			tlsh.unknown0x00000001=0x00000001;
		}

		buf
	}
}

#[derive(Clone)]
struct PeHeader<'data> {
	data: &'data [u8],
	checksum: &'data u32,
	certdir: &'data DataDirectory<pe::RVA<[u8]>>,
	data1: &'data [u8],
	data2: &'data [u8],
	data3: &'data [u8],
}

impl<'data> PeHeader<'data> {
	fn new(pe: &pe::Pe<'data>) -> Result<PeHeader<'data>> {
		let data=try!(pe.ref_pe_header());
		Ok(PeHeader{
			data:data,
			data1:data,
			data2:data,
			data3:data,
			checksum:pe.get_optional_header().get_check_sum(),
			certdir:try!(pe.get_directory_raw(DirectoryEntry::CertificateTable)),
		})
	}

	fn splice<'a>(&'a mut self) -> Box<Read+'a> {
		let data_ptr=&self.data[0] as *const _ as usize;
		let checksum_offset=(self.checksum as *const _ as usize).checked_sub(data_ptr).unwrap();
		let checksum_size=size_of_val(self.checksum);
		let certdir_offset=(self.certdir as *const _ as usize).checked_sub(data_ptr).unwrap();
		let certdir_size=size_of_val(self.certdir);
		assert!(checksum_offset+checksum_size<=self.data.len());
		assert!(certdir_offset+certdir_size<=self.data.len());
		self.data1=&self.data[..checksum_offset];
		self.data2=&self.data[checksum_offset+checksum_size..certdir_offset];
		self.data3=&self.data[certdir_offset+certdir_size..];
		Box::new((self.data1)
			.chain(io::repeat(0).take(checksum_size as u64))
			.chain(self.data2)
			.chain(io::repeat(0).take(certdir_size as u64))
			.chain(self.data3)
		)
	}
}

//====================
//==== Controller ====
//====================

lazy_static!{static ref UNKNOWN_VALUE_ENCOUNTERED: atomic::AtomicBool = atomic::AtomicBool::new(false);}

fn print_unknown_value_msg() {
	println!(
"An unknown value was encountered in the input file. If possible, please send
your input enclave to the authors for further examination. File a GitHub issue
at https://github.com/jethrogb/sgx-utils/issues/new or send an e-mail to
sgx-utils@jbeekman.nl with as much data as you can provide about the enclave.")
}

fn main() {
	let mut args=std::env::args_os();
	let _name=args.next();
	let infile=args.next().expect("Usage: pe2sgxs <in-pe-file> <sgxs-out-file> [sigstruct-out-file]");
	let outfile=args.next().expect("Usage: pe2sgxs <in-pe-file> <sgxs-out-file> [sigstruct-out-file]");
	let sigfile=args.next();

	let mut pebuf=vec![];
	let mut file=File::open(infile).unwrap();
	file.read_to_end(&mut pebuf).unwrap();
	let pe=pe::Pe::new(&pebuf).unwrap();

	let layout=match LayoutInfo::new(&pe) {
		Err(InvalidSgxmetaSection) => { print_unknown_value_msg(); return },
		l @ _ => l.unwrap()
	};
	let mut hasher=<Sha256 as Sha256Digest>::new();

	{
		let mut outfile=File::create(outfile).unwrap();
		let mut out=BroadcastWriter::new(&mut hasher,&mut outfile);
		layout.write(&mut out).unwrap();
	}

	let hash=hasher.finish();
	let msg;
	if layout.sgxmeta.sigstruct.enclavehash!=&hash[..] {
		msg="\nWARNING: does not match SIGSTRUCT.ENCLAVEHASH!";
	} else {
		msg=" (OK)";
	}
	println!("MRENCLAVE: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{}",hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],hash[8],hash[9],hash[10],hash[11],hash[12],hash[13],hash[14],hash[15],hash[16],hash[17],hash[18],hash[19],hash[20],hash[21],hash[22],hash[23],hash[24],hash[25],hash[26],hash[27],hash[28],hash[29],hash[30],hash[31],msg);

	if UNKNOWN_VALUE_ENCOUNTERED.load(atomic::Ordering::Relaxed) {
		print_unknown_value_msg();
	}

	if let Some(sigfile)=sigfile {
		let sigstruct=unsafe{::std::slice::from_raw_parts(&layout.sgxmeta.sigstruct as *const _ as *const u8,size_of::<Sigstruct>())};
		File::create(sigfile).unwrap().write_all(sigstruct).unwrap();
	}
}
