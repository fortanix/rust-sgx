/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

fn main() {
    #[cfg(not(windows))] {
        extern crate protoc_rust;
        use std::env;
        use std::fs::File;
        use std::io::Write;
        use std::path::PathBuf;

        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo should set OUT_DIR"));

        protoc_rust::Codegen::new()
            .out_dir(&out_dir)
            .inputs(&["src/aesm_proto.proto"])
            .run()
            .expect("Running protoc failed.");

        // Because of https://github.com/rust-lang/rfcs/issues/752, we can't `include!` the generated
        // protobufs directly. Instead, we generate a second generated file that can be `include!`-ed.
        // This trick borrowed from rust-mbedtls.

        let mod_aesm_proto = out_dir.join("mod_aesm_proto.rs");
        File::create(&mod_aesm_proto)
            .and_then(|mut f| f.write_all(b"mod aesm_proto;\n"))
            .expect("mod_aesm_proto.rs I/O error");
    }
}
