/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate cc;
use std::env;
use std::ffi::OsStr;
use std::fs::{read_dir, DirEntry};
use std::path::PathBuf;

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let p_c = ["src", "c"].iter().collect::<PathBuf>();
    #[cfg(unix)]
    let p_s = ["src", "asm", &arch].iter().collect::<PathBuf>();
    #[cfg(windows)]
    let p_s = ["src", "obj", &arch].iter().collect::<PathBuf>();

    let extension_filter = |ext| {
        move |f: Result<DirEntry, _>| {
            let f = f.unwrap();
            if f.file_type().unwrap().is_file() {
                let path = f.path();
                if path.extension().and_then(OsStr::to_str) == Some(ext) {
                    return Some(path);
                }
            }
            None
        }
    };

    let mut build = cc::Build::new();

    #[cfg(unix)]
    for path in read_dir(p_s).unwrap().filter_map(extension_filter("S")) {
        build.file(path);
    }
    #[cfg(windows)]
    for path in read_dir(p_s).unwrap().filter_map(extension_filter("o")) {
        build.object(path);
    }
    for path in read_dir(p_c).unwrap().filter_map(extension_filter("c")) {
        build.file(path);
    }


    let name = if env::var("TARGET").unwrap() == "x86_64-fortanix-unknown-sgx" {
        "libc.a"
    } else {
        "librsc.a"
    };

    let mut b = build
        .define(
            "weak_alias(old,new)",
            Some("extern __typeof(old) new __attribute__((alias(#old)))"),
        )
        .flag("-U_FORTIFY_SOURCE")
        .define("_FORTIFY_SOURCE", Some("0"))
        .define("__NO_STRING_INLINES", None)
        .define("__NO_MATH_INLINES", None);
    #[cfg(unix)]
        {
            b = b.flag("-ffreestanding");
        }
    #[cfg(windows)]
        {
            b = b.define("restrict", "__restrict").ar_flag("/NODEFAULTLIB:libc.dll");
        }

    b.warnings(false).compile(name);
}
