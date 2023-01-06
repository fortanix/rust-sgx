/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
use dcap_retrieve_pckid::retrieve_pckid_str;

fn main() {
    match retrieve_pckid_str() {
        Err(e) => {
            eprintln!("ERROR retrieving PCK ID: {}", e);
            std::process::exit(1);
        }
        Ok(pckid) => println!("{}", pckid.to_string()),
    }
}
