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

#[macro_use]
extern crate clap;
extern crate libc;
extern crate rustc_serialize;

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
use std::rc::Rc;

use clap::ArgMatches;

use rustc_serialize::json::DecoderError as JsonError;
use rustc_serialize::Decodable;

use exec::{CommandExt,ExecError};
use num::NumArg;

const TARGET_TRIPLE: &'static str = "x86_64-unknown-none-gnu";

trait JsonDeserialize: Decodable {
	fn from_json_slice(mut v: &[u8]) -> Result<Self,JsonError> {
		use rustc_serialize::json::{Json,Decoder};
		Decodable::decode(&mut Decoder::new(try!(Json::from_reader(&mut v))))
	}
}

impl<T: Decodable> JsonDeserialize for T {}

#[derive(RustcDecodable)]
struct Manifest {
	id: String,
	name: String,
	manifest_path: String,
	targets: Vec<ManifestTarget>,
	dependencies: Vec<ManifestDependency>,
}

#[derive(RustcDecodable)]
struct ManifestTarget {
	kind: Vec<String>,
	name: String,
}

#[derive(RustcDecodable)]
struct ManifestDependency {
	name: String,
	req: String,
}

impl Manifest {
	fn check(&self) -> Result<(),Error> {
		let dependency=try!(self.dependencies.iter().find(|dep|dep.name=="enclave").ok_or(Error::ManifestNoEnclaveDependency));
		if dependency.req!=concat!("= ",crate_version!()) {
			return Err(Error::ManifestEnclaveDependencyInvalidVersion(dependency.req.to_owned().into()));
		}
		Ok(())
	}

	fn get_targets(&self, target_arg: Option<&[Cow<OsStr>]>) -> Result<(Vec<TargetArg>,bool),Error> {
		if let Some(target_arg)=target_arg {
			match target_arg[0].to_str().map(|s|&s[2..]) {
				Some(k @ "bin") | Some(k @ "example") => {
					// find matching target from manifest
					self.targets.iter()
						.find(|target| &*target_arg[1]==&*target.name && target.kind.iter().any(|el|el==k) )
						.map(|target| (vec![TargetArg::new(&target_arg[0],&target.name)],false) )
						.ok_or( Error::TargetNotFound(os_str_err(&target_arg[0]),os_str_err(&target_arg[1])) )
				}
				_ => Err(Error::TargetInvalidType(os_str_err(&target_arg[0])))
			}
		} else {
			// find all bin targets in manifest
			let targets: Vec<_>=self.targets.iter()
				.filter(|target| target.kind.iter().any(|k|k=="bin") )
				.map(|target| TargetArg::new("--bin",&target.name) )
				.collect();
			if targets.is_empty() {
				Err(Error::TargetNoTargets)
			} else {
				Ok((targets,true))
			}
		}
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
	ManifestNoEnclaveDependency,
	ManifestEnclaveDependencyInvalidVersion(String),
	TargetNoTargets,
	TargetNotFound(String,String),
	TargetInvalidType(String),
	TargetInvalidCmdline(String),
	CargoReadManifestInvalidCmdline,
	CargoReadManifestExec(ExecError),
	CargoReadManifestJson(JsonError),
	CargoRustcExec(ExecError),
	CargoRustcNoOutput(IoError),
	ConvCantFindConv(IoError),
	ConvExec(ExecError),
	ConvNoOutput(IoError),
}

fn os_str_err(s: &OsStr) -> String {
	s.to_string_lossy().into_owned()
}

impl fmt::Display for Error {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		use Error::*;
		match *self {
			ManifestNoEnclaveDependency => write!(fmt,"This crate does not seem to have a dependency on libenclave."),
			ManifestEnclaveDependencyInvalidVersion(ref dep_v) => write!(fmt,"There is a version mismatch between libenclave-tools ({}) and the libenclave dependency version ({}).",crate_version!(),dep_v),
			TargetNoTargets => write!(fmt,"You didn't specify a target and there are no `bin' targets. If you're getting this error after upgrading libenclave-tools, check out the upgrade instructions."),
			TargetNotFound(ref e1, ref e2) => write!(fmt,"Target {} {} not found.",e1,e2),
			TargetInvalidType(ref err) => write!(fmt,"A {} target was specified, but only --bin and --example targets are supported.",err),
			TargetInvalidCmdline(ref err) => write!(fmt,"The {} argument is invalid.",err),
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
	threads: usize,
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
			threads: usize::parse_arg(args.value_of("threads").unwrap()),
			cargo_args: args.values_of_os("cargo-opts").map(|args|args.map(Cow::Borrowed).collect()).unwrap_or(vec![]),
		}
	}

	fn into_builders(self) -> Result<Vec<Builder<'args>>,Error> {
		let manifest=try!(self.read_manifest());
		try!(manifest.check());

		let (targets,rustc_specify_target)=try!(manifest.get_targets(try!(self.target_arg())));

		let rc_builder=Rc::new(self);
		let rc_manifest=Rc::new(manifest);

		let map_tempfile=Rc::new(try!(rc_builder.target_path(&rc_manifest,&TargetArg::new("MAPFILE",format!("libenclave-{}.map",rc_manifest.name)))));

		targets.into_iter().map(|target_arg| {
			let rc_manifest=rc_manifest.clone();
			let rc_builder=rc_builder.clone();

			let bin_artifact=try!(rc_builder.target_path(&rc_manifest,&target_arg));
			let sgxs_artifact=naming::output_lib_name(&bin_artifact,"sgxs").unwrap(/* panic here indicates bug in cargo */).into_os_string();

			Ok(Builder{
				mode:rc_builder,
				manifest:rc_manifest,
				target_arg:match rustc_specify_target {
					true => Some(target_arg),
					false => None,
				},
				bin_artifact:bin_artifact,
				map_tempfile:map_tempfile.clone(),
				sgxs_artifact:sgxs_artifact,
			})
		}).collect()
	}

	fn manifest_path_arg(&self) -> Result<Option<&[Cow<OsStr>]>,Error> {
		if let Some(pos)=self.cargo_args.iter().rposition(|arg|&**arg=="--manifest-path") {
			if pos+1>=self.cargo_args.len() { return Err(Error::CargoReadManifestInvalidCmdline) }
			Ok(Some(&self.cargo_args[pos..pos+2]))
		} else {
			Ok(None)
		}
	}

	fn target_arg(&self) -> Result<Option<&[Cow<OsStr>]>,Error> {
		let target_flags: &[&OsStr] = &["--lib".as_ref(),"--bin".as_ref(),"--example".as_ref(),"--test".as_ref(),"--bench".as_ref()];

		if let Some((pos,arg))=self.cargo_args.iter().enumerate().find(|&(_,arg)|target_flags.contains(&&**arg)) {
			if &**arg=="--lib" {
				Ok(Some(&self.cargo_args[pos..pos+1]))
			} else {
				if pos+1>=self.cargo_args.len() { return Err(Error::TargetInvalidCmdline(os_str_err(&arg))) }
				Ok(Some(&self.cargo_args[pos..pos+2]))
			}
		} else {
			Ok(None)
		}
	}

	fn read_manifest(&self) -> Result<Manifest,Error> {
		let mut cargo=Command::new("cargo");
		cargo.arg("read-manifest")
		.stderr(ProcessIo::inherit());

		if let Some(extra_args)=try!(self.manifest_path_arg()) {
			cargo.args(extra_args);
		}

		let out=try!(cargo.output_ext(self.verbose).map_err(Error::CargoReadManifestExec));
		Manifest::from_json_slice(&out.stdout).map_err(Error::CargoReadManifestJson)
	}

	fn target_path(&self, manifest: &Manifest, target_arg: &TargetArg) -> Result<OsString,Error> {
		let release=self.cargo_args.iter().any(|arg|&**arg=="--release");

		let mut buf=Path::new(&manifest.manifest_path).with_file_name("target");
		buf.push(TARGET_TRIPLE);
		buf.push(if release { "release" } else { "debug" });
		if &target_arg.ty == "--example" { buf.push("examples") };
		buf.push(&target_arg.name);
		Ok(buf.into())
	}
}

struct TargetArg {
	ty: OsString,
	name: OsString,
}

impl TargetArg {
	fn new<T: AsRef<OsStr>, N: AsRef<OsStr>>(ty: T, name: N) -> TargetArg {
		TargetArg {
			ty: ty.as_ref().to_owned(),
			name: name.as_ref().to_owned(),
		}
	}
}

struct Builder<'args> {
	mode: Rc<BuilderMode<'args>>,
	manifest: Rc<Manifest>,
	target_arg: Option<TargetArg>,
	bin_artifact: OsString,
	sgxs_artifact: OsString,
	map_tempfile: Rc<OsString>,
}

impl<'args> Builder<'args> {
	fn cargo_rustc(&mut self) -> Result<(),Error> {
		let mut cargo=Command::new("cargo");
		cargo.env("LIBENCLAVE_NO_WARNING","1");
		cargo.env("LIBENCLAVE_MAP_FILE",&*self.map_tempfile);
		cargo.arg("rustc");
		if let Some(TargetArg{ref ty,ref name})=self.target_arg {
			cargo.arg(ty);
			cargo.arg(name);
		}

		if self.mode.verbose { cargo.arg("--verbose"); }
		if self.mode.quiet { cargo.arg("--quiet"); }
		cargo.arg("--color");
		cargo.arg(if self.mode.color { "always" } else { "never" });

		cargo.args(&self.mode.cargo_args);
		cargo.args(&["--target",TARGET_TRIPLE]);

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
			"-Wl,--export-dynamic",
			"-Wl,--version-script="/*append later*/
		].join(" ")).into();
		link_args.push(&*self.map_tempfile);
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
		cmd.arg(format!("{}",self.mode.ssaframesize));
		cmd.arg("--threads");
		cmd.arg(format!("{}",self.mode.threads));
		cmd.arg("--heap-size");
		cmd.arg(format!("0x{:x}",self.mode.heap_size));
		cmd.arg("--stack-size");
		cmd.arg(format!("0x{:x}",self.mode.stack_size));

		cmd.arg(&self.bin_artifact);
		cmd.status_ext(self.mode.verbose).map_err(Error::ConvExec)
	}

	fn build(mut self) -> Result<(),Error> {
		try!(self.cargo_rustc());
		try!(fs::metadata(&self.bin_artifact).map_err(Error::CargoRustcNoOutput));

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
			.arg(Arg::with_name("ssaframesize")         .long("ssaframesize").value_name("PAGES").validator(u32::validate_arg  ).default_value("1").help("Specify SSAFRAMESIZE"))
			.arg(Arg::with_name("threads")   .short("t").long("threads")     .value_name("N")    .validator(usize::validate_arg).default_value("1").help("Specify the number of threads"))
			.arg(Arg::with_name("heap-size") .short("H").long("heap-size")   .value_name("BYTES").validator(u64::validate_arg  ).required(true)    .help("Specify heap size"))
			.arg(Arg::with_name("stack-size").short("S").long("stack-size")  .value_name("BYTES").validator(u64::validate_arg  ).required(true)    .help("Specify stack size"))
		).get_matches();

	let args=args.subcommand_matches("build-enclave").unwrap();
	
	if args.is_present("debug") {
		writeln!(std::io::stderr(),"Error: the --debug flag is no longer supported. Use --features directly to use the SGX debugging features.").expect("failed printing to stderr");
		std::process::exit(1);
	}

	let mut error = false;
	match BuilderMode::new(&args).into_builders() {
		Err(e) => {
			writeln!(std::io::stderr(),"ERROR: {}",e).expect("failed printing to stderr");
			error = true;
		}
		Ok(builders) => {
			for builder in builders {
				if let Err(e) = builder.build() {
					writeln!(std::io::stderr(),"ERROR: {}",e).expect("failed printing to stderr");
					error = true;
				}
			}
		}
	}

	if error { std::process::exit(1); }
}
