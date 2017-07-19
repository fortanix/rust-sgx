/*
 * Tools for building and linking enclaves using libenclave.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#[macro_use]
extern crate clap;
extern crate sgxs as sgxs_crate;
extern crate sgx_isa;
extern crate xmas_elf;

use std::io::{repeat,Read,Error as IoError};
use std::mem::{transmute,replace};
use std::path::{Path,PathBuf};
use std::fs::File;

use xmas_elf::ElfFile;
use xmas_elf::sections::{SHN_UNDEF,SectionData};
use xmas_elf::symbol_table::{Entry,DynEntry64 as DynSymEntry};
use xmas_elf::header::Class as HeaderClass;
use xmas_elf::dynamic::{Dynamic as DynEntry,Tag as DynTag};
use xmas_elf::program::{SegmentData,Type as PhType};

use sgx_isa::{Tcs,PageType,secinfo_flags};
use sgxs_crate::sgxs::{SgxsWrite,CanonicalSgxsWriter,self,SecinfoTruncated,Error as SgxsError};
use sgxs_crate::util::{size_fit_page,size_fit_natural};

#[derive(Debug)]
pub enum Error {
	DynamicSymbolUndefined(String),                      // "Found undefined dynamic symbol: {}"
	DynamicSymbolDuplicate(&'static str),                // "Found symbol twice: {}"
	DynamicSymbolMissing(Vec<&'static str>),             // "These dynamic symbols are missing: {}"
	DynamicSymbolIncorrectSize{name:&'static str,expected:u64,actual:u64},
	DynamicSymbolTableNotInDynsymSection,                // ".dynsym section is not a dynamic symbol table!"
	DynamicSymbolTableNotFound,                          // "Could not found dynamic symbol table!"
	DynamicSymbolEnclaveSizeNotAligned,                  // "ENCLAVE_SIZE symbol is not naturally aligned"
	DynEntryUnsupportedPLTGOT,                           // "Unsupported dynamic entry: PLT/GOT"
	DynEntryUnsupportedInitFunction,                     // "Unsupported dynamic entry: .init functions"
	DynEntryUnsupportedFiniFunction,                     // "Unsupported dynamic entry: .fini functions"
	DynEntryUnsupportedImplicitReloc,                    // "Unsupported dynamic entry: relocations with implicit addend"
	DynEntryDuplicateDtRela,                             // "Found dynamic entry twice: DT_RELA"
	DynEntryDuplicateDtRelacount,                        // "Found dynamic entry twice: DT_RELACOUNT"
	DynEntryFoundDtRelaButNotDtRelacount,                // "DT_RELA found, but DT_RELACOUNT not found"
	DynEntryFoundDtRelacountButNotDtRela,                // "DT_RELACOUNT found, but DT_RELA not found"
	DynamicSectionNotInPtDynamicSegment,                 // "PT_DYNAMIC segment is not a dynamic section!"
	DynamicSectionNotFound,                              // "Could not found dynamic section!"
	NotesNotInNoteLibenclaveSection,                     // ".note.libenclave section is not a note section!"
	RelocationInvalid{section:u32,rtype:u32},            // "Invalid relocation: section={} type={}"
	RelocationOutsideWritableSegment(u64),               // "Relocation at 0x{:016x} outside of writable segments"
	RelocationInvalidCount{expected:u64,actual:usize},   // "Expected {} relocations, found {}"
	ElfClassNot64,                                       // "Only 64-bit supported!"
	NoLoadableSegments,                                  // "No loadable segments found"
	XmasElfError(&'static str),
	Sgxs(SgxsError),
}

impl From<&'static str> for Error {
	fn from(err: &'static str) -> Error {
		Error::XmasElfError(err)
	}
}

impl From<SgxsError> for Error {
	fn from(err: SgxsError) -> Error {
		Error::Sgxs(err)
	}
}

#[allow(non_snake_case)]
struct Symbols<'a> {
	sgx_entry: &'a DynSymEntry,
	HEAP_BASE: &'a DynSymEntry,
	HEAP_SIZE: &'a DynSymEntry,
	RELA: &'a DynSymEntry,
	RELACOUNT: &'a DynSymEntry,
	ENCLAVE_SIZE: &'a DynSymEntry,
}

struct Dynamic<'a> {
	rela: &'a DynEntry<u64>,
	relacount: &'a DynEntry<u64>,
}

struct Splice(u64,u64);

impl PartialEq for Splice {
	fn eq(&self, other: &Self) -> bool { self.0.eq(&other.0) }
}
impl Eq for Splice {}
impl PartialOrd for Splice {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { self.0.partial_cmp(&other.0) }
}
impl Ord for Splice {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0.cmp(&other.0) }
}

pub struct LayoutInfo<'a> {
	elf: ElfFile<'a>,
	sym: Symbols<'a>,
	dyn: Option<Dynamic<'a>>,
	ssaframesize: u32,
	heap_size: u64,
	stack_size: u64,
	threads: usize,
}

macro_rules! read_syms {
	($($name:ident),* in $syms:ident : $elf:ident) => {{
		$(let mut $name=None;)*
		for sym in $syms.iter().skip(1) {
			if sym.shndx()==SHN_UNDEF {
				return Err(Error::DynamicSymbolUndefined(try!(sym.get_name(&$elf)).to_string()));
			} $(else if try!(sym.get_name(&$elf))==stringify!($name) {
				if replace(&mut $name,Some(sym)).is_some() {
					return Err(Error::DynamicSymbolDuplicate(stringify!($name)));
				}
			})*
		}
		if let ($(Some($name)),*)=($($name),*) {
			Symbols{$($name:$name),*}
		} else {
			let mut missing=vec![];
			$(if $name.is_none() {
				missing.push(stringify!($name))
			})*
			return Err(Error::DynamicSymbolMissing(missing));
		}
	}}
}

macro_rules! check_size {
	($syms:ident.$name:ident == $size:expr) => {{
		let size=$syms.$name.size();
		if size!=$size {
			return Err(Error::DynamicSymbolIncorrectSize{name:stringify!($name),expected:$size,actual:size});
		}
	}}
}

impl<'a> LayoutInfo<'a> {
	#[allow(non_snake_case)]
	fn check_symbols(elf: &ElfFile<'a>) -> Result<Symbols<'a>,Error> {
		if let Some(dynsym)=elf.find_section_by_name(".dynsym") {
			if let SectionData::DynSymbolTable64(syms) = try!(dynsym.get_data(&elf)) {
				let syms=read_syms!(sgx_entry, HEAP_BASE, HEAP_SIZE, RELA, RELACOUNT, ENCLAVE_SIZE in syms : elf);

				check_size!(syms.HEAP_BASE    == 8);
				check_size!(syms.HEAP_SIZE    == 8);
				check_size!(syms.RELA         == 8);
				check_size!(syms.RELACOUNT    == 8);
				check_size!(syms.ENCLAVE_SIZE == 8);

				if (syms.ENCLAVE_SIZE.value() & (syms.ENCLAVE_SIZE.size()-1)) != 0 {
					return Err(Error::DynamicSymbolEnclaveSizeNotAligned);
				}

				Ok(syms)
			} else {
				Err(Error::DynamicSymbolTableNotInDynsymSection)
			}
		} else {
			Err(Error::DynamicSymbolTableNotFound)
		}
	}

	fn check_dynamic(elf: &ElfFile<'a>) -> Result<Option<Dynamic<'a>>,Error> {
		use xmas_elf::dynamic::Tag::*;
		const DT_RELACOUNT:	DynTag<u64> = OsSpecific(0x6ffffff9);
		const DT_RELCOUNT:  DynTag<u64> = OsSpecific(0x6ffffffa);
		//const DT_PLTPADSZ:  DynTag<u64> = OsSpecific(0x6ffffdf9);
		//const DT_PLTPAD:    DynTag<u64> = OsSpecific(0x6ffffefd);

		if let Some(dynh)=elf.program_iter().find(|ph|ph.get_type()==Ok(PhType::Dynamic)) {
			if let SegmentData::Dynamic64(dyns) = try!(dynh.get_data(&elf)) {
				let mut rela=None;
				let mut relacount=None;

				for dyn in dyns {
					match try!(dyn.get_tag()) {
						// Some entries for PLT/GOT checking are currently
						// commented out. I *think* that if there were an actual
						// PLT/GOT problem, that would be caught by the remaining
						// entries or check_relocs().
						PltRelSize | PltRel | JmpRel /*| Pltgot | DT_PLTPADSZ | DT_PLTPAD*/ =>
							return Err(Error::DynEntryUnsupportedPLTGOT),
						Init | InitArray | InitArraySize =>
							return Err(Error::DynEntryUnsupportedInitFunction),
						Fini | FiniArray | FiniArraySize =>
							return Err(Error::DynEntryUnsupportedFiniFunction),
						Rel | RelSize | RelEnt | DT_RELCOUNT =>
							return Err(Error::DynEntryUnsupportedImplicitReloc),
						Rela => if replace(&mut rela,Some(dyn)).is_some() {
							return Err(Error::DynEntryDuplicateDtRela);
						},
						DT_RELACOUNT => if replace(&mut relacount,Some(dyn)).is_some() {
							return Err(Error::DynEntryDuplicateDtRelacount);
						},
						_ => {}
					}
				}

				match (rela,relacount) {
					(Some(rela),Some(relacount)) => Ok(Some(Dynamic{rela:rela,relacount:relacount})),
					(None,None) => Ok(None),
					(_,None) => Err(Error::DynEntryFoundDtRelaButNotDtRelacount),
					(None,_) => Err(Error::DynEntryFoundDtRelacountButNotDtRela),
				}
			} else {
				Err(Error::DynamicSectionNotInPtDynamicSegment)
			}
		} else {
			Err(Error::DynamicSectionNotFound)
		}
	}

	fn check_relocs(elf: &ElfFile<'a>, dynamic: Option<&Dynamic<'a>>) -> Result<(),Error> {
		use xmas_elf::program::FLAG_W;

		const R_X86_64_RELATIVE: u32 = 8;

		let writable_ranges=elf.program_iter().filter_map(|ph|
			if ph.get_type()==Ok(PhType::Load) && (ph.flags()&FLAG_W)==FLAG_W {
				Some(ph.virtual_addr()..(ph.virtual_addr()+ph.mem_size()))
			} else { None }).collect::<Vec<_>>();

		let mut count=0;
		for section in elf.section_iter() {
			if let SectionData::Rela64(relas) = try!(section.get_data(&elf)) {
				count+=relas.len();
				for rela in relas {
					let shind=rela.get_symbol_table_index();
					let rtype=rela.get_type();
					if (shind,rtype) != (0,R_X86_64_RELATIVE) {
						return Err(Error::RelocationInvalid{section:shind,rtype:rtype});
					}
					let offset=rela.get_offset();
					if writable_ranges.iter().find(|r|offset>=r.start && (offset+8)<=r.end).is_none() {
						return Err(Error::RelocationOutsideWritableSegment(offset));
					}
				}
			}
		}

		let target=dynamic.and_then(|d|d.relacount.get_val().ok()).unwrap_or(0);
		if count as u64 != target {
			return Err(Error::RelocationInvalidCount{expected:target,actual:count});
		}

		Ok(())
	}
	
	fn _check_debug(elf: &ElfFile<'a>) -> Result<bool,Error> {
		if let Some(notes)=elf.find_section_by_name(".note.libenclave") {
			if let SectionData::Note64(note,data) = try!(notes.get_data(&elf)) {
				Ok(note.name(data)=="libenclave DEBUG")
			} else {
				Err(Error::NotesNotInNoteLibenclaveSection)
			}
		} else {
			Ok(false)
		}
	}

	pub fn new(elf: ElfFile<'a>, ssaframesize: u32, heap_size: u64, stack_size: u64, threads: usize) -> Result<LayoutInfo<'a>,Error>  {
		if let HeaderClass::SixtyFour=elf.header.pt1.class() {} else {
			return Err(Error::ElfClassNot64);
		}
		let sym=try!(Self::check_symbols(&elf));
		let dyn=try!(Self::check_dynamic(&elf));
		try!(Self::check_relocs(&elf,dyn.as_ref()));

		Ok(LayoutInfo{
			elf:elf,
			sym:sym,
			dyn:dyn,
			ssaframesize:ssaframesize,
			heap_size:heap_size,
			stack_size:stack_size,
			threads:threads,
		})
	}

	pub fn write_elf_segments<W: SgxsWrite>(&self, writer: &mut CanonicalSgxsWriter<W>, heap_addr: u64, enclave_size: u64) -> Result<(),Error> {
		let mut splices=[
			Splice(self.sym.HEAP_BASE.value(),heap_addr),
			Splice(self.sym.HEAP_SIZE.value(),self.heap_size),
			Splice(self.sym.RELA.value(),self.dyn.as_ref().and_then(|d|d.rela.get_ptr().ok()).unwrap_or(0)),
			Splice(self.sym.RELACOUNT.value(),self.dyn.as_ref().and_then(|d|d.relacount.get_val().ok()).unwrap_or(0)),
			Splice(self.sym.ENCLAVE_SIZE.value(),enclave_size),
		];
		splices.sort(); // `Splice` sorts by address
		let mut cur_splice=splices.iter().peekable();

		for ph in self.elf.program_iter().filter(|ph|ph.get_type()==Ok(PhType::Load)) {
			use xmas_elf::program::{FLAG_R,FLAG_W,FLAG_X};
			let mut secinfo=SecinfoTruncated{flags:PageType::Reg.into()};
			if (ph.flags()&FLAG_R)!= 0 { secinfo.flags.insert(secinfo_flags::R); }
			if (ph.flags()&FLAG_W)!= 0 { secinfo.flags.insert(secinfo_flags::W); }
			if (ph.flags()&FLAG_X)!= 0 { secinfo.flags.insert(secinfo_flags::X); }
			let start=ph.virtual_addr();
			let base=start&!0xfff;
			let end=start+ph.mem_size();
			let base_data;
			if let SegmentData::Undefined(data)=try!(ph.get_data(&self.elf)) {
				base_data=data;
			} else {
				// Reachable if xmas-elf changes definitition of SegmentData
				unreachable!();
			}

			let mut data: Box<Read>;
			let mut cur_ptr=base;

			if cur_splice.peek().map(|s|cur_ptr==s.0).unwrap_or(false) {
				data=Box::new(&unsafe{transmute::<&u64,&[u8;8]>(&cur_splice.next().unwrap().1)}[..]);
			} else if cur_ptr==start {
				data=Box::new(base_data);
			} else {
				data=Box::new(repeat(0).take(start-cur_ptr).chain(&base_data[..]));
			}

			while cur_splice.peek().map(|s|s.0>=base && (s.0+8)<end).unwrap_or(false) {
				let splice=cur_splice.next().unwrap();

				let nd=data.take(splice.0-base);
				cur_ptr=splice.0+8;
				let nd=nd.chain(&unsafe{transmute::<&u64,&[u8;8]>(&splice.1)}[..]);
				if cur_ptr<start {
					data=Box::new(nd.chain(repeat(0).take(start-cur_ptr).chain(&base_data[..])));
				} else {
					data=Box::new(nd.chain(&base_data[(cur_ptr-start) as usize..]));
				}
			}

			try!(writer.write_pages(Some(&mut data),(size_fit_page(end-base)/0x1000) as usize,Some(base),secinfo))
		}

		Ok(())
	}

	pub fn write<W: SgxsWrite>(&self, writer: &mut W) -> Result<(),Error> {
		let max_addr=try!(self.elf.program_iter().filter_map(|ph|
			if ph.get_type()==Ok(PhType::Load) {
				Some(ph.virtual_addr()+ph.mem_size())
			} else { None }).max().ok_or(Error::NoLoadableSegments));

		let heap_addr=size_fit_page(max_addr);
		let mut thread_start=heap_addr+self.heap_size;
		const THREAD_GUARD_SIZE: u64=0x10000;
		const TLS_SIZE: u64=0x1000;
		let nssa=1u32;
		let thread_size=THREAD_GUARD_SIZE+self.stack_size+TLS_SIZE+(1+(nssa as u64)*(self.ssaframesize as u64))*0x1000;
		let enclave_size=size_fit_natural(thread_start+(self.threads as u64)*thread_size);

		let mut writer=try!(CanonicalSgxsWriter::new(writer,sgxs::MeasECreate{size:enclave_size,ssaframesize:self.ssaframesize}));

		// Output ELF sections
		try!(self.write_elf_segments(&mut writer,heap_addr,enclave_size));

		// Output heap
		let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
		try!(writer.write_pages::<&[u8]>(None,(self.heap_size as usize)/0x1000,Some(heap_addr),secinfo));

		for _ in 0..self.threads {
			let stack_addr=thread_start+THREAD_GUARD_SIZE;
			let stack_tos=stack_addr+self.stack_size;
			let tls_addr=stack_tos;
			let tcs_addr=tls_addr+TLS_SIZE;

			// Output stack
			let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
			try!(writer.write_pages::<&[u8]>(None,(self.stack_size as usize)/0x1000,Some(stack_addr),secinfo));

			// Output TLS
			let tls=unsafe{std::mem::transmute::<_,[u8;24]>([stack_tos,0u64,0u64])};
			let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
			try!(writer.write_pages(Some(&mut &tls[..]),1,Some(tls_addr),secinfo));

			// Output TCS, SSA
			let tcs=Tcs {
				ossa: tcs_addr+0x1000,
				nssa: nssa,
				oentry: self.sym.sgx_entry.value(),
				ofsbasgx: tls_addr,
				ogsbasgx: stack_tos,
				fslimit: 0xfff,
				gslimit: 0xfff,
				..Tcs::default()
			};
			let tcs=unsafe{std::mem::transmute::<_,[u8;4096]>(tcs)};
			let secinfo=SecinfoTruncated{flags:PageType::Tcs.into()};
			try!(writer.write_page(Some(&mut &tcs[..]),Some(tcs_addr),secinfo));
			let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
			try!(writer.write_pages::<&[u8]>(None,(nssa*self.ssaframesize) as usize,None,secinfo));

			thread_start+=thread_size;
		}

		Ok(())
	}
}

/////////////////
// Driver code //
/////////////////

mod naming;
mod num;

use clap::ArgMatches;
use num::NumArg;

#[derive(Debug)]
enum DriverError {
	ElfRead(IoError),
	Elf2Sgxs(Error),
}

impl From<Error> for DriverError {
	fn from(err: Error) -> DriverError {
		DriverError::Elf2Sgxs(err)
	}
}

fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>,IoError> {
	let mut f=try!(File::open(path));
	let mut buf=vec![];
	try!(f.read_to_end(&mut buf));
	Ok(buf)
}

fn main_result(args: ArgMatches) -> Result<(),DriverError> {
	let ssaframesize=u32  ::parse_arg(args.value_of("ssaframesize").unwrap());
	let heap_size=   u64  ::parse_arg(args.value_of("heap-size")   .unwrap());
	let stack_size=  u64  ::parse_arg(args.value_of("stack-size")  .unwrap());
	let threads=     usize::parse_arg(args.value_of("threads")     .unwrap());

	let srclib=PathBuf::from(args.value_of("lib").unwrap());
	let srcbuf=try!(read_file(&srclib).map_err(DriverError::ElfRead));
	let srcelf=ElfFile::new(&srcbuf);
	let layout=try!(LayoutInfo::new(srcelf,ssaframesize,heap_size,stack_size,threads));

	let mut outfile=args.value_of("output").map(|out|File::create(out)).unwrap_or_else(||File::create(naming::output_lib_name(&srclib,"sgxs").expect("Missing filename"))).unwrap();
	try!(layout.write(&mut outfile));

	Ok(())
}

fn main() {
	use clap::{Arg,App,AppSettings};

	let args = App::new("libenclave-elf2sgxs")
		.about("Convert a libenclave dynamic library into an SGXS enclave")
		.version(crate_version!())
		.setting(AppSettings::UnifiedHelpMessage)
		.arg(Arg::with_name("ssaframesize")         .long("ssaframesize").value_name("PAGES").validator(u32::validate_arg  ).default_value("1").help("Specify SSAFRAMESIZE"))
		.arg(Arg::with_name("threads")   .short("t").long("threads")     .value_name("N")    .validator(usize::validate_arg).default_value("1").help("Specify the number of threads"))
		.arg(Arg::with_name("heap-size") .short("H").long("heap-size")   .value_name("BYTES").validator(u64::validate_arg  ).required(true)    .help("Specify heap size"))
		.arg(Arg::with_name("stack-size").short("S").long("stack-size")  .value_name("BYTES").validator(u64::validate_arg  ).required(true)    .help("Specify stack size"))
		.arg(Arg::with_name("output").short("o").long("output").value_name("FILE").help("Specify output file"))
		.arg(Arg::with_name("lib").index(1).required(true).help("Path to the dynamic library to be converted"))
		.get_matches();

	if let Err(e)=main_result(args) {
		println!("Error: {:?}",e);
		std::process::exit(1);
	};
}
