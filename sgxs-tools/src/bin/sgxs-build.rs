/*
 * Build an SGXS by concatenating input files.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

extern crate sgxs as sgxs_crate;
extern crate sgx_isa;

use std::fs::{self,File};
use std::io::stdout;

use sgx_isa::{Tcs,PageType,secinfo_flags,SecinfoFlags};
use sgxs_crate::sgxs::{CanonicalSgxsWriter,self,SecinfoTruncated};
use sgxs_crate::util::{size_fit_page,size_fit_natural};

enum Block {
	Blob{flags:SecinfoFlags,file:String,pages:usize},
	TcsSsa{nssa:u32},
}
use Block::*;

fn main() {
	let mut args=std::env::args().peekable();
	args.next();

	let mut advance=false;
	let mut ssaframesize=1;
	if let Some(arg)=args.peek() {
		if arg.starts_with("ssaframesize=") {
			ssaframesize=arg[13..].parse::<u32>().expect("ssaframesize must be a number");
			advance=true;
		}
	}
	if advance { args.next(); }

	let mut blocks=vec![];
	for arg in args {
		let mut arg_split=arg.splitn(2,"=");
		let (k,v)=match (arg_split.next(),arg_split.next(),arg_split.next()) {
			(Some(k),Some(v),None) => (k,v),
			_ => panic!("Invalid argument: «{}»",arg)
		};
		if k=="ssaframesize" {
			panic!("ssaframesize must be the first argument if specified");
		} else if k=="tcs" {
			if v.starts_with("nssa:") {
				let nssa=v[5..].parse::<u32>().expect("nssa must be a number");
				blocks.push(TcsSsa{nssa:nssa});
			} else {
				panic!("tcs must be specified as tcs=nssa:N");
			}
		} else if k=="r" || k=="rw" || k=="rx" || k=="rwx" {
			let flags=k.as_bytes().iter().fold(PageType::Reg.into(),|f,&c|{
				f|match c {
					b'r' =>secinfo_flags::R,
					b'w' =>secinfo_flags::W,
					b'x' =>secinfo_flags::X,
					_ => unreachable!()
				}
			});
			blocks.push(Blob{flags:flags,file:v.to_string(),pages:(size_fit_page(fs::metadata(v).unwrap().len())>>12) as usize});
		} else {
			panic!("Invalid argument: «{}»",arg);
		}
	}

	let pages=blocks.iter().map(|block|{
		match block { &Blob{pages,..} => pages,	&TcsSsa{nssa} => 1+((nssa*ssaframesize) as usize), }
	}).fold(0,std::ops::Add::add);

	let mut out=stdout();
	let mut writer=CanonicalSgxsWriter::new(&mut out,sgxs::MeasECreate{size:size_fit_natural((pages as u64)*0x1000),ssaframesize:ssaframesize},true).unwrap();

	for block in blocks {
		match block {
			Blob{file,flags,pages} => {
				let secinfo=SecinfoTruncated{flags:flags};
				writer.write_pages(Some(&mut File::open(file).unwrap()),pages,None,secinfo).unwrap();
			},
			TcsSsa{nssa} => {
				let tcs=Tcs {
					ossa: writer.offset()+0x1000,
					nssa: nssa,
					oentry: 0,
					ofsbasgx: 0,
					ogsbasgx: 0,
					fslimit: 0xfff,
					gslimit: 0xfff,
					..Tcs::default()
				};
				let tcs=unsafe{std::mem::transmute::<_,[u8;4096]>(tcs)};
				let secinfo=SecinfoTruncated{flags:PageType::Tcs.into()};
				writer.write_page(Some(&mut &tcs[..]),None,secinfo).unwrap();
				let secinfo=SecinfoTruncated{flags:secinfo_flags::R|secinfo_flags::W|PageType::Reg.into()};
				writer.write_pages(Some(&mut &[][..]),(nssa*ssaframesize) as usize,None,secinfo).unwrap();
			}
		}
	}
}
