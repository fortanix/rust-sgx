/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate sgx_isa;
extern crate sgxs as sgxs_crate;

use std::fs::{self, File};
use std::io::stdout;

use sgx_isa::{PageType, SecInfoFlags, Tcs};
use crate::sgxs_crate::sgxs::{self, CanonicalSgxsWriter, SecinfoTruncated};
use crate::sgxs_crate::util::{size_fit_natural, size_fit_page};

enum Block {
    Blob {
        flags: SecInfoFlags,
        file: String,
        pages: usize,
    },
    TcsSsa {
        nssa: u32,
    },
}
use crate::Block::*;

fn main() {
    let mut args = std::env::args().peekable();
    args.next();

    let mut advance = false;
    let mut ssaframesize = 1;
    if let Some(arg) = args.peek() {
        if arg.starts_with("ssaframesize=") {
            ssaframesize = arg[13..]
                .parse::<u32>()
                .expect("ssaframesize must be a number");
            advance = true;
        }
    }
    if advance {
        args.next();
    }

    let mut blocks = vec![];
    for arg in args {
        let mut arg_split = arg.splitn(2, "=");
        let (k, v) = match (arg_split.next(), arg_split.next(), arg_split.next()) {
            (Some(k), Some(v), None) => (k, v),
            _ => panic!("Invalid argument: «{}»", arg),
        };
        if k == "ssaframesize" {
            panic!("ssaframesize must be the first argument if specified");
        } else if k == "tcs" {
            if v.starts_with("nssa:") {
                let nssa = v[5..].parse::<u32>().expect("nssa must be a number");
                blocks.push(TcsSsa { nssa: nssa });
            } else {
                panic!("tcs must be specified as tcs=nssa:N");
            }
        } else if k == "r" || k == "rw" || k == "rx" || k == "rwx" {
            let flags = k.as_bytes().iter().fold(PageType::Reg.into(), |f, &c| {
                f | match c {
                    b'r' => SecInfoFlags::R,
                    b'w' => SecInfoFlags::W,
                    b'x' => SecInfoFlags::X,
                    _ => unreachable!(),
                }
            });
            blocks.push(Blob {
                flags: flags,
                file: v.to_string(),
                pages: (size_fit_page(fs::metadata(v).unwrap().len()) >> 12) as usize,
            });
        } else {
            panic!("Invalid argument: «{}»", arg);
        }
    }

    let pages = blocks
        .iter()
        .map(|block| match block {
            &Blob { pages, .. } => pages,
            &TcsSsa { nssa } => 1 + ((nssa * ssaframesize) as usize),
        })
        .fold(0, std::ops::Add::add);

    let mut out = stdout();
    let mut writer = CanonicalSgxsWriter::new(
        &mut out,
        sgxs::MeasECreate {
            size: size_fit_natural((pages as u64) * 0x1000),
            ssaframesize: ssaframesize,
        },
        true,
    )
    .unwrap();

    for block in blocks {
        match block {
            Blob { file, flags, pages } => {
                let secinfo = SecinfoTruncated { flags: flags };
                writer
                    .write_pages(Some(&mut File::open(file).unwrap()), pages, None, secinfo)
                    .unwrap();
            }
            TcsSsa { nssa } => {
                let tcs = Tcs {
                    ossa: writer.offset() + 0x1000,
                    nssa: nssa,
                    oentry: 0,
                    ofsbasgx: 0,
                    ogsbasgx: 0,
                    fslimit: 0xfff,
                    gslimit: 0xfff,
                    ..Tcs::default()
                };
                let tcs = unsafe { std::mem::transmute::<_, [u8; 4096]>(tcs) };
                let secinfo = SecinfoTruncated {
                    flags: PageType::Tcs.into(),
                };
                writer
                    .write_page(Some(&mut &tcs[..]), None, secinfo)
                    .unwrap();
                let secinfo = SecinfoTruncated {
                    flags: SecInfoFlags::R | SecInfoFlags::W | PageType::Reg.into(),
                };
                writer
                    .write_pages(
                        Some(&mut &[][..]),
                        (nssa * ssaframesize) as usize,
                        None,
                        secinfo,
                    )
                    .unwrap();
            }
        }
    }
}
