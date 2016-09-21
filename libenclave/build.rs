extern crate gcc;

use std::env;
use std::path::{Path,PathBuf};
use std::fs::File;
use std::io::{stderr,Write};

/// If `prefix` is a prefix of `filename`, return the remainder of the path
/// after the prefix. Otherwise, return `None`.
fn remove_prefix<'a>(prefix: &Path, filename: &'a Path) -> Option<&'a Path> {
	let mut prefix=prefix.iter();
	let mut filename=filename.iter();
	loop {
		let remaining=filename.as_path();
		match (filename.next(),prefix.next()) {
			(Some(a),Some(b)) if a==b => continue,
			(_,None) => return Some(remaining),
			_ => return None,
		}
	}
}

// Building as packaging dependency if $OUT_DIR == .../target/package/[^/]+/target/$PROFILE/build/enclave-\x{16}/out
fn building_as_packaging_dependency() -> bool {
	let out_dir: PathBuf=env::var_os("OUT_DIR").expect("OUT_DIR environment variable not set?").into();
	let env_profile=env::var_os("PROFILE").expect("PROFILE environment variable not set?");

	let mut iter=out_dir.iter().rev();

	if let (Some(out),Some(enclave),Some(build),Some(profile),Some(target),Some(_),Some(package),Some(target2))=(iter.next(),iter.next(),iter.next(),iter.next(),iter.next(),iter.next(),iter.next(),iter.next()) {
		(
			target2=="target" &&
			package=="package" &&
			target=="target" &&
			profile==&env_profile[..] &&
			build=="build" &&
			enclave.to_str().map(|s|s.starts_with("enclave-")).unwrap_or(false) &&
			out=="out"
		)
	} else {
		false
	}
}

// Building stand-alone if $OUT_DIR == $CARGO_MANIFEST_DIR/target/$PROFILE/build/$CRATE-\x{16}/out
fn building_as_dependency() -> bool {
	let out_dir: PathBuf=env::var_os("OUT_DIR").expect("OUT_DIR environment variable not set?").into();
	let cmf_dir: PathBuf=env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR environment variable not set?").into();
	let env_profile=env::var_os("PROFILE").expect("PROFILE environment variable not set?");

	let mut iter=if let Some(dir)=remove_prefix(&cmf_dir,&out_dir) {
		dir.iter()
	} else {
		return true
	};

	if let (Some(target),Some(profile),Some(build),Some(enclave),Some(out))=(iter.next(),iter.next(),iter.next(),iter.next(),iter.next()) {
		!(
			target=="target" &&
			profile==&env_profile[..] &&
			build=="build" &&
			enclave.to_str().map(|s|s.starts_with("enclave-")).unwrap_or(false) &&
			out=="out"
		)
	} else {
		true
	}
}

fn main() {
	if building_as_dependency() && !building_as_packaging_dependency() {
		if env::var_os("LIBENCLAVE_NO_WARNING").is_none() {
			let _=writeln!(stderr(),"Dependents of libenclave must use the libenclave build tools!");
			let _=writeln!(stderr(),"");
			let _=writeln!(stderr(),"Use «cargo build-enclave» instead of «cargo build»");
			std::process::exit(1);
		}
		
		let mut f=File::create(env::var_os("LIBENCLAVE_MAP_FILE").unwrap()).unwrap();
		f.write_all(b"{
global:
	sgx_entry;
	HEAP_BASE;
	HEAP_SIZE;
	RELA;
	RELACOUNT;
	ENCLAVE_SIZE;
local:
	*;
};").unwrap();
	}

	gcc::compile_library("libaes.a", &["src/aes/asm_impl.S"]);
	
	let mut entry=gcc::Config::new();
	entry.file("src/entry.S");
	if std::env::var_os("CARGO_FEATURE_DEBUG").is_some() {
		entry.define("DEBUG",Some("DEBUG"));
	}
	entry.compile("libentry.a");
}
