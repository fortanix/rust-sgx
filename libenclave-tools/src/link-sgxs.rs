/*
 * Link a libenclave static library into an SGXS enclave
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![feature(float_extras)]

#[macro_use]
extern crate clap;
extern crate sgxs as sgxs_crate;
extern crate sgx_isa;
extern crate xmas_elf;

mod naming;
mod num;
mod elf2sgxs;
mod exec;

use std::path::{Path,PathBuf};
use std::fs::File;
use std::ffi::OsStr;
use std::process::Command;
use std::io::{Read,Write,Error as IoError};

use xmas_elf::ElfFile;

use clap::ArgMatches;

use exec::{CommandExt,ExecError};
use num::NumArg;

#[derive(Debug)]
enum Error {
	InvalidInputFilename,
	TempFileIo(IoError),
	LinkExec(ExecError),
	ElfRead(IoError),
	Elf2Sgxs(elf2sgxs::Error),
}

impl From<elf2sgxs::Error> for Error {
	fn from(err: elf2sgxs::Error) -> Error {
		Error::Elf2Sgxs(err)
	}
}

const ENTRY_ASM: &'static str = include_str!("entry.S");
const ENCLAVE_MAP: &'static str = include_str!("enclave.map");

fn create_temp_file<T: AsRef<[u8]>>(path: &Path, data: T) -> Result<(),Error> {
	let mut file=try!(File::create(path).map_err(Error::TempFileIo));
	file.write_all(data.as_ref()).map_err(Error::TempFileIo)
}

fn link(srclib: PathBuf, debug: bool) -> Result<PathBuf,Error> {
	let dstlib=try!(naming::output_lib_name(&srclib,"so").ok_or(Error::InvalidInputFilename));
	let entry_asm=srclib.with_file_name("entry.S");
	let enclave_map=srclib.with_file_name("enclave.map");
	try!(create_temp_file(&entry_asm,ENTRY_ASM));
	try!(create_temp_file(&enclave_map,ENCLAVE_MAP));
	let mut map_arg=OsStr::new("-Wl,--version-script=").to_owned();
	map_arg.push(enclave_map);
	let mut gcc=Command::new("gcc");
	let link_args=["-fuse-ld=gold","-nostdlib","-shared","-Bstatic","-Wl,--gc-sections",
				   /*"-Wl,--strip-all",*/"-Wl,-z,text","-Wl,-z,norelro","-Wl,--rosegment",
				   "-Wl,--no-undefined","-Wl,--error-unresolved-symbols","-Wl,--no-undefined-version",
				   "-Wl,-Bsymbolic"];
	gcc.arg("-o").arg(&dstlib).arg(&entry_asm).args(&link_args).arg(&map_arg).arg(&srclib);
	if debug { gcc.arg("-DDEBUG"); }
	try!(gcc.status_ext(false).map_err(Error::LinkExec));
	Ok(dstlib)
}

fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>,IoError> {
	let mut f=try!(File::open(path));
	let mut buf=vec![];
	try!(f.read_to_end(&mut buf));
	Ok(buf)
}

fn main_result(args: ArgMatches) -> Result<(),Error> {
	let ssaframesize=u32::parse_arg(args.value_of("ssaframesize").unwrap());
	let heap_size=   u64::parse_arg(args.value_of("heap-size")   .unwrap());
	let stack_size=  u64::parse_arg(args.value_of("stack-size")  .unwrap());
	let debug=args.is_present("debug");

	let srclib=PathBuf::from(args.value_of("staticlib").unwrap());
	let dstlib=try!(link(srclib,debug));
	let dstbuf=try!(read_file(&dstlib).map_err(Error::ElfRead));
	let dstelf=ElfFile::new(&dstbuf);
	let layout=try!(elf2sgxs::LayoutInfo::new(dstelf,ssaframesize,heap_size,stack_size,debug));

	let mut outfile=args.value_of("output").map(|out|File::create(out)).unwrap_or_else(||File::create(dstlib.with_extension("sgxs"))).unwrap();
	try!(layout.write(&mut outfile));

	Ok(())
}

fn main() {
	use clap::{Arg,App,AppSettings};

	let args = App::new("link-sgxs")
		.about("Link a libenclave static library into an SGXS enclave")
		.version(crate_version!())
		.setting(AppSettings::UnifiedHelpMessage)
		.arg(Arg::with_name("debug").short("d").long("debug").help("Link with the debug runtime"))
		.arg(Arg::with_name("ssaframesize")         .long("ssaframesize").value_name("PAGES").validator(u32::validate_arg).default_value("1").help("Specify SSAFRAMESIZE"))
		.arg(Arg::with_name("heap-size") .short("H").long("heap-size")   .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify heap size"))
		.arg(Arg::with_name("stack-size").short("S").long("stack-size")  .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify stack size"))
		.arg(Arg::with_name("output").short("o").long("output").value_name("FILE").help("Specify output file"))
		.arg(Arg::with_name("staticlib").index(1).required(true).help("Path to the static library to be linked"))
		.arg(Arg::with_name("agpl-source").long("agpl-source").conflicts_with_all(&["staticlib","heap-size","stack-size"]).help("Print AGPL-licensed files"))
		.after_help("IMPORTANT NOTICE:
	The object code output by this program will include object code licensed
	under the GNU Affero General Public License (AGPL). Therefore, distributing
	object code output by this program requires complying with the AGPL. To see
	the source code for the AGPL-licensed object code, run this program with
	--agpl-source.")
		.get_matches();

	if args.is_present("agpl-source") {
		print!("{}",ENTRY_ASM);
		return;
	}

	if let Err(e)=main_result(args) {
		println!("Error: {:?}",e);
		std::process::exit(1);
	};
}
