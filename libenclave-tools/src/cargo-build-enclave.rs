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
use std::collections::HashMap;
use std::fs;
use std::borrow::Cow;

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
	features: HashMap<String,Vec<String>>,
}

#[derive(Deserialize)]
struct ManifestTarget {
	name: String,
	kind: Vec<String>,
}

#[derive(Deserialize)]
struct ManifestDependency {
	name: String,
	req: String,
}

impl Manifest {
	fn check(&self) -> Result<(),Error> {
		if !self.targets.iter().any(|target|target.name==self.name && target.kind.iter().any(|kind|kind=="staticlib")) {
			return Err(Error::ManifestNotStaticlib);
		}
		let dependency=try!(self.dependencies.iter().find(|dep|dep.name=="enclave").ok_or(Error::ManifestNoEnclaveDependency));
		if dependency.req!=concat!("= ",crate_version!()) {
			return Err(Error::ManifestEnclaveDependencyInvalidVersion(dependency.req.to_owned()));
		}
		Ok(())
	}

	fn find_debug_feature(&self) -> Result<&str,Error> {
		let mut found_feature=None;
		for (feature,deps) in self.features.iter() {
			if deps.iter().any(|dep|dep=="enclave/debug") {
				if found_feature.is_none() {
					found_feature=Some(&feature[..]);
				} else {
					return Err(Error::ManifestMultipleDebugFeatures);
				}
			}
		}
		found_feature.ok_or(Error::ManifestNoDebugFeature)
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
	ManifestNoDebugFeature,
	ManifestMultipleDebugFeatures,
	ManifestNotStaticlib,
	ManifestNoEnclaveDependency,
	ManifestEnclaveDependencyInvalidVersion(String),
	StdoutError(IoError),
	CargoReadManifestInvalidCmdline,
	CargoReadManifestExec(ExecError),
	CargoReadManifestJson(JsonError),
	CargoBuildInvalidCmdline,
	CargoBuildExec(ExecError),
	CargoBuildNoOutput(IoError),
	LinkCantFindLink(IoError),
	LinkExec(ExecError),
	LinkNoOutput(IoError),
}

struct BuilderMode<'args> {
	debug: bool,
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
			debug: args.is_present("debug"),
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

		let staticlib_artifact=try!(self.target_path(&manifest));
		let sgxs_artifact=naming::output_lib_name(&staticlib_artifact,"sgxs").unwrap(/* panic here indicates bug in cargo */).into_os_string();

		let builder=Builder{
			mode:self,
			manifest:manifest,
			staticlib_artifact:staticlib_artifact,
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
		target.push(".a");

		Ok(target)
	}
}

struct Builder<'args> {
	mode: BuilderMode<'args>,
	manifest: Manifest,
	staticlib_artifact: OsString,
	sgxs_artifact: OsString,
}

impl<'args> Builder<'args> {
	fn cargo_build(&mut self) -> Result<(),Error> {
		if self.mode.debug {
			let feature=try!(self.manifest.find_debug_feature());
			match self.mode.cargo_args.iter().position(|arg|&**arg=="--features") {
				Some(pos) => {
					let features_arg=try!(self.mode.cargo_args.get_mut(pos+1).ok_or(Error::CargoBuildInvalidCmdline));
					features_arg.to_mut().push(" ");
					features_arg.to_mut().push(feature);
				},
				None => {
					self.mode.cargo_args.push(Cow::Owned("--features".into()));
					self.mode.cargo_args.push(Cow::Owned(feature.into()));
				}
			}
		}

		let mut cargo=Command::new("cargo");
		cargo.env("LIBENCLAVE_NO_WARNING","1").arg("build");

		if self.mode.verbose { cargo.arg("--verbose"); }
		if self.mode.quiet { cargo.arg("--quiet"); }
		cargo.arg("--color");
		cargo.arg(if self.mode.color { "always" } else { "never" });

		cargo.args(&self.mode.cargo_args);
		cargo.status_ext(self.mode.verbose).map_err(Error::CargoBuildExec)
	}

	fn find_link_sgxs() -> Result<Command,Error> {
		let arg0=try!(env::current_exe().map_err(Error::LinkCantFindLink));
		Ok(Command::new(arg0.with_file_name("link-sgxs")))
	}

	fn link(&self) -> Result<(),Error> {
		let mut cmd=try!(Self::find_link_sgxs());

		if self.mode.debug { cmd.arg("--debug"); }
		cmd.arg("--ssaframesize");
		cmd.arg(format!("0x{:x}",self.mode.ssaframesize));
		cmd.arg("--heap-size");
		cmd.arg(format!("0x{:x}",self.mode.heap_size));
		cmd.arg("--stack-size");
		cmd.arg(format!("0x{:x}",self.mode.stack_size));

		cmd.arg(&self.staticlib_artifact);
		cmd.status_ext(self.mode.verbose).map_err(Error::LinkExec)
	}

	fn build(mut self) -> Result<(),Error> {
		try!(self.cargo_build());
		try!(fs::metadata(&self.staticlib_artifact).map_err(Error::CargoBuildNoOutput));

		try!(self.say_status("Linking",&self.manifest.id));
		try!(self.link());
		try!(fs::metadata(&self.sgxs_artifact).map_err(Error::LinkNoOutput));

		Ok(())
	}

	fn say_status(&self, status: &str, message: &str) -> Result<(),Error> {
		let stdout=std::io::stdout();
		let mut l=stdout.lock();
		say_status(&mut l,self.mode.color,status,message).map_err(Error::StdoutError)
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
			.arg(Arg::with_name("debug").short("d").long("debug").help("Link with the debug runtime"))
			.arg(Arg::with_name("cargo-opts").index(1).multiple(true).help("Options to be passed to `cargo build`"))
			.arg(Arg::with_name("ssaframesize")         .long("ssaframesize").value_name("PAGES").validator(u32::validate_arg).default_value("1").help("Specify SSAFRAMESIZE"))
			.arg(Arg::with_name("heap-size") .short("H").long("heap-size")   .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify heap size"))
			.arg(Arg::with_name("stack-size").short("S").long("stack-size")  .value_name("BYTES").validator(u64::validate_arg).required(true)    .help("Specify stack size"))
		).get_matches();

	let args=args.subcommand_matches("build-enclave").unwrap();

	if let Err(e)=BuilderMode::new(&args).into_builder().and_then(Builder::build) {
		println!("Error: {:?}",e);
		std::process::exit(1);
	};
}
