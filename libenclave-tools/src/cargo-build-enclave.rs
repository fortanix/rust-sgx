/*
 * Cargo frontend for libenclave
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#[macro_use]
extern crate clap;
extern crate libc;
extern crate serde;
extern crate serde_json;

mod naming;
mod exec;
mod num;

use std::process::{Command,Stdio as ProcessIo};
use std::env;
use std::ffi::{OsStr,OsString};
use std::path::Path;
use std::io::{Write,Error as IoError};
use std::fs;
use std::borrow::Cow;
use std::fmt;

use clap::ArgMatches;

use serde_json::error::Error as JsonError;

use exec::{CommandExt,ExecError};
use num::NumArg;

trait JsonDeserialize: serde::Deserialize {
	fn from_json_slice(v: &[u8]) -> Result<Self,JsonError> {
		serde_json::from_slice(v)
	}
}

impl<T: serde::Deserialize> JsonDeserialize for T {}

#[derive(Deserialize)]
struct Manifest {
	name: String,
	id: String,
	manifest_path: String,
	targets: Vec<ManifestTarget>,
	dependencies: Vec<ManifestDependency>,
}

#[derive(Deserialize)]
struct ManifestTarget {
	kind: Vec<String>,
}

#[derive(Deserialize)]
struct ManifestDependency {
	name: String,
	req: String,
}

impl Manifest {
	fn check(&self) -> Result<(),Error> {
		if !(self.targets.len()==1 && self.targets[0].kind==["dylib"]) {
			return Err(Error::ManifestTargetNotDylib);
		}
		let dependency=try!(self.dependencies.iter().find(|dep|dep.name=="enclave").ok_or(Error::ManifestNoEnclaveDependency));
		if dependency.req!=concat!("= ",crate_version!()) {
			return Err(Error::ManifestEnclaveDependencyInvalidVersion(dependency.req.to_owned().into()));
		}
		Ok(())
	}
}

fn say_status<W: Write>(writer: &mut W, color: bool, status: &str, message: &str) -> Result<(),IoError> {
	if color { try!(writer.write_all(b"\x1b[0;32;1m")); }
	try!(write!(writer, "{:>12}", status));
	if color { try!(writer.write_all(b"\x1b[0m")); }
	try!(write!(writer, " {}\n", message));
	writer.flush()
}

#[derive(Debug)]
enum Error {
	ManifestTargetNotDylib,
	ManifestNoEnclaveDependency,
	ManifestEnclaveDependencyInvalidVersion(String),
	CargoReadManifestInvalidCmdline,
	CargoReadManifestExec(ExecError),
	CargoReadManifestJson(JsonError),
	CargoRustcExec(ExecError),
	CargoRustcNoOutput(IoError),
	ConvCantFindConv(IoError),
	ConvExec(ExecError),
	ConvNoOutput(IoError),
}

impl fmt::Display for Error {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		use Error::*;
		match *self {
			ManifestTargetNotDylib => write!(fmt,"This crate's manifest specifies more than one target, or the only target is not a `dylib' target. If you're getting this error after upgrading libenclave-tools, check out the upgrade instructions."),
			ManifestNoEnclaveDependency => write!(fmt,"This crate does not seem to have a dependency on libenclave."),
			ManifestEnclaveDependencyInvalidVersion(ref dep_v) => write!(fmt,"There is a version mismatch between libenclave-tools ({}) and the libenclave dependency version ({}).",crate_version!(),dep_v),
			CargoReadManifestInvalidCmdline => write!(fmt,"There was an error executing `cargo read-manifest': the --manifest-path argument is invalid."),
			CargoReadManifestExec(ref err) => write!(fmt,"There was an error executing `cargo read-manifest': {}",err),
			CargoReadManifestJson(ref err) => write!(fmt,"There was an error parsing the JSON output of `cargo read-manifest': {}",err),
			CargoRustcExec(ref err) => write!(fmt,"There was an error executing `cargo rustc': {}",err),
			CargoRustcNoOutput(ref err) => write!(fmt,"Output artifact not found after executing `cargo rustc': {}",err),
			ConvCantFindConv(ref err) => write!(fmt,"Couldn't find `libenclave-elf2sgxs' executable: {}",err),
			ConvExec(ref err) => write!(fmt,"There was an error executing `libenclave-elf2sgxs': {}",err),
			ConvNoOutput(ref err) => write!(fmt,"Output artifact not found after executing `libenclave-elf2sgxs': {}",err),
		}
	}
}

struct BuilderMode<'args> {
	verbose: bool,
	color: bool,
	quiet: bool,
	ssaframesize: u32,
	heap_size: u64,
	stack_size: u64,
	cargo_args: Vec<Cow<'args,OsStr>>,
}

fn color_detect(arg: &str) -> bool {
	if arg=="always" {
		true
	} else if arg=="none" {
		false
	} else if arg=="auto" {
		unsafe { libc::isatty(1 /*stdout*/)!=0 }
	} else {
		unreachable!() // clap would've caught this possibility earlier
	}
}

impl<'args> BuilderMode<'args> {
	fn new(args: &'args ArgMatches) -> BuilderMode<'args> {
		BuilderMode{
			verbose: args.is_present("verbose"),
			quiet: args.is_present("quiet"),
			color: color_detect(args.value_of("color").unwrap()),
			ssaframesize: u32::parse_arg(args.value_of("ssaframesize").unwrap()),
			heap_size: u64::parse_arg(args.value_of("heap-size").unwrap()),
			stack_size: u64::parse_arg(args.value_of("stack-size").unwrap()),
			cargo_args: args.values_of_os("cargo-opts").map(|args|args.map(Cow::Borrowed).collect()).unwrap_or(vec![]),
		}
	}

	fn into_builder(self) -> Result<Builder<'args>,Error> {
		let manifest=try!(self.read_manifest());
		try!(manifest.check());

		let dylib_artifact=try!(self.target_path(&manifest));
		let map_tempfile=naming::output_lib_name(&dylib_artifact,"map").unwrap(/* panic here indicates bug in cargo */).into_os_string();
		let sgxs_artifact=naming::output_lib_name(&dylib_artifact,"sgxs").unwrap(/* panic here indicates bug in cargo */).into_os_string();

		let builder=Builder{
			mode:self,
			manifest:manifest,
			dylib_artifact:dylib_artifact,
			map_tempfile:map_tempfile,
			sgxs_artifact:sgxs_artifact,
		};

		Ok(builder)
	}

	fn manifest_path_arg(&self) -> Result<Option<&[Cow<OsStr>]>,()> {
		if let Some(pos)=self.cargo_args.iter().rposition(|arg|&**arg=="--manifest-path") {
			if pos+1>=self.cargo_args.len() { return Err(()) }
			Ok(Some(&self.cargo_args[pos..pos+2]))
		} else {
			Ok(None)
		}
	}

	fn read_manifest(&self) -> Result<Manifest,Error> {
		let mut cargo=Command::new("cargo");
		cargo.arg("read-manifest")
		.stderr(ProcessIo::inherit());

		match self.manifest_path_arg() {
			Err(_) => return Err(Error::CargoReadManifestInvalidCmdline),
			Ok(Some(extra_args)) => {cargo.args(extra_args);},
			Ok(_) => {},
		}

		let out=try!(cargo.output_ext(self.verbose).map_err(Error::CargoReadManifestExec));
		Manifest::from_json_slice(&out.stdout).map_err(Error::CargoReadManifestJson)
	}

	fn target_path(&self, manifest: &Manifest) -> Result<OsString,Error> {
		let mut buf=Path::new(&manifest.manifest_path).with_file_name("target");

		let release=self.cargo_args.iter().any(|arg|&**arg=="--release");

		buf.push(if release { "release" } else { "debug" });

		buf.push("lib");
		let mut target=buf.into_os_string();
		target.push(&manifest.name.replace("-","_"));
		target.push(".so");

		Ok(target)
	}
}

struct Builder<'args> {
	mode: BuilderMode<'args>,
	manifest: Manifest,
	dylib_artifact: OsString,
	sgxs_artifact: OsString,
	map_tempfile: OsString,
}

impl<'args> Builder<'args> {
	fn cargo_rustc(&mut self) -> Result<(),Error> {
		let mut cargo=Command::new("cargo");
		cargo.env("LIBENCLAVE_NO_WARNING","1");
		cargo.env("LIBENCLAVE_MAP_FILE",&self.map_tempfile);
		cargo.args(&["rustc","--lib"]);

		if self.mode.verbose { cargo.arg("--verbose"); }
		if self.mode.quiet { cargo.arg("--quiet"); }
		cargo.arg("--color");
		cargo.arg(if self.mode.color { "always" } else { "never" });

		cargo.args(&self.mode.cargo_args);

		let mut link_args: OsString=("link-args=".to_string()+&[
			"-fuse-ld=gold",
			"-nostdlib",
			"-shared",
			"-Wl,-e,sgx_entry",
			"-Wl,-Bstatic",
			"-Wl,--gc-sections",
			"-Wl,-z,text",
			"-Wl,-z,norelro",
			"-Wl,--rosegment",
			"-Wl,--no-undefined",
			"-Wl,--error-unresolved-symbols",
			"-Wl,--no-undefined-version",
			"-Wl,-Bsymbolic",
			"-Wl,--version-script="/*append later*/
		].join(" ")).into();
		link_args.push(&self.map_tempfile);
		cargo.args(&["--","-C"]).arg(&link_args);

		cargo.status_ext(self.mode.verbose).map_err(Error::CargoRustcExec)
	}

	fn find_elf2sgxs() -> Result<Command,Error> {
		let arg0=try!(env::current_exe().map_err(Error::ConvCantFindConv));
		Ok(Command::new(arg0.with_file_name("libenclave-elf2sgxs")))
	}

	fn sgxsconv(&self) -> Result<(),Error> {
		let mut cmd=try!(Self::find_elf2sgxs());

		cmd.arg("--ssaframesize");
		cmd.arg(format!("0x{:x}",self.mode.ssaframesize));
		cmd.arg("--heap-size");
		cmd.arg(format!("0x{:x}",self.mode.heap_size));
		cmd.arg("--stack-size");
		cmd.arg(format!("0x{:x}",self.mode.stack_size));

		cmd.arg(&self.dylib_artifact);
		cmd.status_ext(self.mode.verbose).map_err(Error::ConvExec)
	}

	fn build(mut self) -> Result<(),Error> {
		try!(self.cargo_rustc());
		try!(fs::metadata(&self.dylib_artifact).map_err(Error::CargoRustcNoOutput));

		self.say_status("SGXS Convert",&self.manifest.id);
		try!(self.sgxsconv());
		try!(fs::metadata(&self.sgxs_artifact).map_err(Error::ConvNoOutput));

		Ok(())
	}

	fn say_status(&self, status: &str, message: &str) {
		let stderr=std::io::stderr();
		let mut l=stderr.lock();
		say_status(&mut l,self.mode.color,status,message).expect("failed printing to stderr");
	}
}

fn main() {
	use clap::{Arg,App,AppSettings,SubCommand};

	let args = App::new("cargo")
		.bin_name("cargo")
		.version(concat!("cargo-build-enclave-",crate_version!()))
		.setting(AppSettings::SubcommandRequired)
		.subcommand(SubCommand::with_name("build-enclave")
			.about("Cargo frontend for libenclave")
			.version(crate_version!())
			.setting(AppSettings::UnifiedHelpMessage)
			.setting(AppSettings::TrailingVarArg)
			.usage("cargo build-enclave -H <heap-size> -S <stack-size> [OPTIONS] [--] [<opts for cargo build>...]")
			.arg(Arg::with_name("verbose").short("v").long("verbose").help("Use verbose output"))
			.arg(Arg::with_name("quiet").short("q").long("quiet").help("No output printed to stdout"))
			.arg(Arg::with_name("color").value_name("WHEN").possible_values(&["auto", "always", "never"]).default_value("auto").long("color").help("Coloring"))
			.arg(Arg::with_name("debug").short("d").long("debug").help("(ignored)"))
			.arg(Arg::with_name("cargo-opts").index(1).multiple(true).help("Options to be passed to `cargo build`"))
			.arg(Arg::with_name("ssaframesize")         .long("ssaframesize").value_name("PAGES").validator(u32::validate_arg).default_value("1").help("Specify SSAFRAMESIZE"))
			.arg(Arg::with_name("heap-size") .short("H").long("heap-size")   .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify heap size"))
			.arg(Arg::with_name("stack-size").short("S").long("stack-size")  .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify stack size"))
		).get_matches();

	let args=args.subcommand_matches("build-enclave").unwrap();
	
	if args.is_present("debug") {
		writeln!(std::io::stderr(),"Error: the --debug flag is no longer supported. Use --features directly to use the SGX debugging features.").expect("failed printing to stderr");
		std::process::exit(1);
	}

	if let Err(e)=BuilderMode::new(&args).into_builder().and_then(Builder::build) {
		writeln!(std::io::stderr(),"ERROR: {}",e).expect("failed printing to stderr");
		std::process::exit(1);
	};
}
