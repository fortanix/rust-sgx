/*
 * SGXS signing utility.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

extern crate sgxs;
extern crate clap;
extern crate regex;
extern crate sgx_isa;
extern crate num;

use std::io::Write;
use std::fs::File;
use std::mem::transmute;
use std::borrow::Borrow;

use regex::Regex;

use num::{Num,Unsigned};

use sgx_isa::{Sigstruct,AttributesFlags,Miscselect};
use sgxs::crypto::{RsaPrivateKeyOps,RsaPrivateKey};
use sgxs::sigstruct::Signer;

fn write_sigstruct(path: &str, sig: Sigstruct) {
	File::create(path).expect("Unable to open output file")
		.write_all(&mut unsafe{transmute::<_,[u8;1808]>(sig)}).expect("Unable to write output file");
}

const DATE_REGEX: &'static str = "^[:digit:]{8}$";
const NUM_REGEX: &'static str = "^([:digit:]+|0x[:xdigit:]+)$";
const NUM_NUM_REGEX: &'static str = "^([:digit:]+|0x[:xdigit:]+)(/([:digit:]+|0x[:xdigit:]+))?$";
const HASH_REGEX: &'static str = "^[:xdigit:]{64}$";

fn date_validate(s: String) -> Result<(),String> {
	if Regex::new(DATE_REGEX).unwrap().is_match(&s) {
		Ok(())
	} else {
		Err(String::from("date must be specified as YYYYMMDD"))
	}
}

fn num_validate(s: String) -> Result<(),String> {
	if Regex::new(NUM_REGEX).unwrap().is_match(&s) {
		Ok(())
	} else {
		Err(String::from("the value must be numeric"))
	}
}

fn num_num_validate(s: String) -> Result<(),String> {
	if Regex::new(NUM_REGEX).unwrap().is_match(&s) || Regex::new(NUM_NUM_REGEX).unwrap().is_match(&s) {
		Ok(())
	} else {
		Err(String::from("the value must be a number or number/number"))
	}
}

fn hash_validate(s: &str) -> Result<(),String> {
	if Regex::new(HASH_REGEX).unwrap().is_match(s) {
		Ok(())
	} else {
		Err(String::from("the hash must be 64 hexadecimal characters"))
	}
}

fn parse_num<T: Copy + Unsigned + Num<FromStrRadixErr=std::num::ParseIntError>>(s: &str) -> T {
	if s.starts_with("0x") {
		Num::from_str_radix(&s[2..],16).unwrap()
	} else {
		Num::from_str_radix(s,10).unwrap()
	}
}

fn parse_num_num<T: Copy + Unsigned + Num<FromStrRadixErr=std::num::ParseIntError>>(s: &str) -> (T,T) {
	let mut splits=s.splitn(2,"/");
	let num1=parse_num(splits.next().unwrap());
	let num2=splits.next().map(parse_num).unwrap_or(num1);
	(num1,num2)
}

fn hex_digit_to_num(ascii: u8) -> u8 {
	match ascii {
		b'0' ... b'9' => ascii-b'0',
		b'A' ... b'F' => ascii-b'A'+10,
		b'a' ... b'f' => ascii-b'a'+10,
		_ => panic!("Tried to convert non-hex character")
	}
}

fn parse_hexstr<S: Borrow<str>>(s: S) -> Vec<u8> {
	let s=s.borrow();
	let mut vec=Vec::with_capacity(s.len()/2);
	for chunk in s.as_bytes().chunks(2) {
		vec.push(hex_digit_to_num(chunk[0])<<4|hex_digit_to_num(chunk[1]))
	}
	vec
}

fn args_desc<'a>() -> clap::App<'a,'a> {
	use clap::Arg;

	clap::App::new("sgxs-sign")
		.about("SGXS SIGSTRUCT generator")
		.arg(Arg::with_name("swdefined")               .short("s").long("swdefined") .takes_value(true)     .validator(num_validate)    .help("Sets the SWDEFINED field (default: 0)"))
		.arg(Arg::with_name("miscselect/miscmask")     .short("m").long("miscselect").takes_value(true)     .validator(num_num_validate).help("Sets the MISCSELECT and inverse MISCMASK fields (default: 0/0)"))
		.arg(Arg::with_name("attributes/attributemask").short("a").long("attributes").takes_value(true)     .validator(num_num_validate).help("Sets the lower ATTRIBUTES and inverse lower ATTRIBUTEMASK fields (default: 0x4/0x2)"))
		.arg(Arg::with_name("xfrm/xfrmmask")           .short("x").long("xfrm")      .takes_value(true)     .validator(num_num_validate).help("Sets the ATTRIBUTES.XFRM and inverse ATTRIBUTEMASK.XFRM fields (default: 0x3/0)"))
		.arg(Arg::with_name("32bit")                              .long("32")                                                           .help("Unsets the MODE64BIT bit in the ATTRIBUTES field, sets MODE64BIT in the ATTRIBUTEMASK field"))
		.arg(Arg::with_name("debug")                   .short("d").long("debug")                                                        .help("Sets the DEBUG bit in the ATTRIBUTES field, unsets the DEBUG bit in the ATTRIBUTEMASK field"))
		.arg(Arg::with_name("date")                               .long("date")      .value_name("YYYYMMDD").validator(date_validate)   .help("Sets the DATE field (default: today)"))
		.arg(Arg::with_name("isvprodid")               .short("p").long("isvprodid") .takes_value(true)     .validator(num_validate)    .help("Sets the ISVPRODID field (default: 0)"))
		.arg(Arg::with_name("isvsvn")                  .short("v").long("isvsvn")    .takes_value(true)     .validator(num_validate)    .help("Sets the ISVSVN field (default: 0)"))
		.arg(Arg::with_name("key-file")                .short("k").long("key")       .value_name("FILE")    .required(true)             .help("Sets the path to the PEM-encoded RSA private key"))
		.arg(Arg::with_name("input-hash")                         .long("in-hash")                                                      .help("<input> specifies the ENCLAVEHASH field directly, instead of an SGXS file"))
		.arg(Arg::with_name("input")                                                                        .required(true)             .help("The enclave SGXS file that will be hashed"))
		.arg(Arg::with_name("output")                                                                       .required(true)             .help("The output SIGSTRUCT file"))
		.after_help("NUMERIC ARGUMENTS:
    Unsigned values only. It is possible to specify hexadecimal numbers using
    the 0x prefix.

MISCSELECT / ATTRIBUTES MASKS:
    Specify the *inverse* of the mask you want. If you don't specify a mask,
    the same value will be used twice.")
}

fn do_sign<'a>(matches: &clap::ArgMatches<'a>, key: &RsaPrivateKey) -> Sigstruct {
	let mut signer=Signer::new();

	if let Some((sel,mask))=matches.value_of("miscselect/miscmask").map(parse_num_num::<u32>) {
		let sel =Miscselect::from_bits(sel).unwrap_or_else(||{
			println!("WARNING: Dropping unknown bits in input MISCSELECT!");
			Miscselect::from_bits_truncate(sel)
		});
		signer.miscselect(sel,!mask);
	}

	let (mut attributes,attributemask)=matches.value_of("attributes/attributemask")
		.map(parse_num_num::<u64>).unwrap_or((sgx_isa::attributes_flags::MODE64BIT.bits(),sgx_isa::attributes_flags::DEBUG.bits()));
	let mut attributemask=!attributemask;
	if matches.is_present("32bit") {
		attributes&=!(sgx_isa::attributes_flags::MODE64BIT.bits());
		attributemask|=sgx_isa::attributes_flags::MODE64BIT.bits();
	}
	if matches.is_present("debug") {
		attributes|=sgx_isa::attributes_flags::DEBUG.bits();
		attributemask&=!(sgx_isa::attributes_flags::DEBUG.bits());
	}
	let attributes=AttributesFlags::from_bits(attributes)
		.unwrap_or_else(||{println!("WARNING: Dropping unknown bits in input ATTRIBUTES!");
			AttributesFlags::from_bits_truncate(attributes)});
	signer.attributes_flags(attributes,attributemask);

	matches.value_of("xfrm/xfrmmask").map(parse_num_num::<u64>).map(|(xfrm,xfrmmask)|signer.attributes_xfrm(xfrm,!xfrmmask));

	matches.value_of("swdefined").map(parse_num::<u32>).map(|v|signer.swdefined(v));
	matches.value_of("isvprodid").map(parse_num::<u16>).map(|v|signer.isvprodid(v));
	matches.value_of("isvsvn").map(parse_num::<u16>).map(|v|signer.isvsvn(v));

	if let Some(date)=matches.value_of("date") {
		signer.date(date[0..4].parse::<u16>().unwrap(),date[4..6].parse::<u8>().unwrap(),date[6..8].parse::<u8>().unwrap());
	}

	if matches.is_present("input-hash") {
		let s=matches.value_of("input").unwrap();
		hash_validate(s).unwrap();
		let mut hash=[0u8; 32];
		(&mut hash[..]).write_all(&parse_hexstr(s)).unwrap();
		signer.enclavehash(hash);
	} else {
		let mut sgxsfile=File::open(matches.value_of("input").unwrap()).expect("Unable to open input SGXS file");
		signer.enclavehash_from_stream(&mut sgxsfile).expect("Unable to read input SGXS file");
	}

	signer.sign(key).expect("Error during signing operation")
}

fn main() {
	let matches = args_desc().get_matches();

	let mut keyfile=File::open(matches.value_of("key-file").unwrap()).expect("Unable to open input key file");
	let key=RsaPrivateKey::new(&mut keyfile).expect("Unable to read input key file");

	let sig=do_sign(&matches,&key);
	let enclavehash=sig.enclavehash.clone();

	write_sigstruct(matches.value_of("output").unwrap(),sig);

	println!("ENCLAVEHASH: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} (OK)",enclavehash[0],enclavehash[1],enclavehash[2],enclavehash[3],enclavehash[4],enclavehash[5],enclavehash[6],enclavehash[7],enclavehash[8],enclavehash[9],enclavehash[10],enclavehash[11],enclavehash[12],enclavehash[13],enclavehash[14],enclavehash[15],enclavehash[16],enclavehash[17],enclavehash[18],enclavehash[19],enclavehash[20],enclavehash[21],enclavehash[22],enclavehash[23],enclavehash[24],enclavehash[25],enclavehash[26],enclavehash[27],enclavehash[28],enclavehash[29],enclavehash[30],enclavehash[31]);
}

#[cfg(test)]
include!("../tests/hex_macro.rs");

#[cfg(test)]
#[test]
fn test_sig() {
	const KEY: &'static [u8] = b"-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----";
	const SIGSTRUCT: &'static [u8] = &hex!( _06 _00 _00 _00 _e1 _00 _00 _00 _00
_00 _01 _00 _00 _00 _00 _00 _00 _00 _00 _00 _09 _01 _16 _20 _01 _01 _00 _00 _60
_00 _00 _00 _60 _00 _00 _00 _01 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _f3
_57 _fd _12 _f0 _28 _7b _d9 _24 _ae _74 _d6 _02 _13 _6d _1b _50 _56 _5b _c7 _64
_d5 _91 _d4 _2f _18 _66 _20 _0b _d6 _71 _03 _4d _f1 _e6 _b2 _53 _d6 _3e _12 _04
_6a _d0 _b5 _58 _d6 _9b _d4 _22 _b7 _f8 _24 _87 _23 _46 _5c _9b _b7 _71 _28 _56
_59 _b4 _c9 _dc _9f _70 _70 _07 _91 _34 _da _b0 _1f _01 _3e _77 _23 _22 _33 _4c
_d7 _2f _10 _15 _62 _43 _85 _9c _d6 _44 _4e _f1 _60 _94 _96 _77 _2b _94 _92 _89
_70 _ff _b7 _e2 _95 _7a _e4 _83 _c7 _2a _36 _dd _22 _3e _bf _9c _f1 _eb _95 _ff
_5b _03 _f9 _59 _67 _6b _aa _b1 _8c _2a _ef _a0 _c5 _23 _f7 _11 _77 _5c _bb _a8
_72 _79 _3c _b3 _52 _49 _f5 _ab _69 _b2 _48 _f4 _e6 _d7 _38 _07 _af _b9 _20 _d2
_b4 _4d _61 _6b _de _4a _b4 _2e _0f _7a _a4 _12 _d3 _ab _71 _9c _55 _ee _37 _c4
_bd _01 _92 _cb _ca _c0 _55 _c8 _06 _65 _b6 _55 _d5 _77 _6b _01 _4e _f5 _3d _87
_26 _39 _df _db _4e _62 _10 _9a _a8 _39 _77 _19 _36 _bd _0c _b5 _b7 _9e _5b _fb
_5f _6d _eb _71 _bb _f2 _8b _16 _5b _a5 _09 _1a _0a _4f _37 _03 _e0 _c9 _46 _be
_37 _9e _2f _6d _c3 _9e _74 _27 _1d _43 _9c _eb _53 _1b _c2 _06 _bb _e0 _b8 _5f
_f3 _4e _22 _66 _7d _f2 _d5 _b7 _40 _1e _19 _2f _41 _e3 _27 _b1 _a7 _a8 _f6 _f2
_d3 _6c _c7 _57 _fc _64 _e7 _09 _49 _96 _46 _2b _13 _3e _ce _8c _4c _37 _66 _89
_f7 _22 _23 _f0 _25 _83 _65 _cf _98 _7c _98 _5d _27 _9a _df _3e _2b _20 _fc _c0
_97 _8f _17 _13 _30 _ab _0a _59 _6f _71 _30 _33 _c1 _ca _22 _23 _0a _72 _bf _00
_99 _7e _81 _c8 _6e _66 _02 _d9 _a2 _d6 _94 _ae _95 _41 _8d _1f _5e _6a _32 _d6
_f9 _46 _25 _2d _93 _66 _d2 _e9 _25 _d9 _15 _17 _8f _65 _43 _f6 _fd _23 _fb _82
_a8 _83 _ae _03 _00 _00 _00 _bc _95 _6c _d8 _27 _08 _4b _1b _69 _7c _ee _40 _8a
_03 _84 _c5 _14 _13 _e7 _1b _5f _38 _23 _13 _64 _ad _78 _99 _0e _a6 _8a _36 _e5
_85 _03 _9e _cb _f0 _70 _41 _8d _36 _91 _fa _50 _2d _ee _2a _a6 _c8 _46 _92 _b2
_89 _e3 _ec _19 _bb _22 _03 _51 _58 _c0 _da _4f _f8 _73 _0f _a5 _79 _1f _97 _2b
_ab _1f _f1 _a0 _eb _ea _40 _cf _32 _fc _2d _d8 _9f _a6 _15 _7f _a5 _59 _c4 _46
_70 _9b _8b _77 _c3 _dc _32 _2c _72 _10 _f3 _9c _03 _82 _b3 _93 _00 _92 _bc _02
_69 _01 _f4 _44 _ca _be _fd _12 _f1 _9d _28 _8f _6f _9a _b8 _91 _68 _3e _c5 _2d
_69 _68 _85 _2d _cd _83 _a0 _27 _3f _37 _2e _36 _54 _fa _16 _0c _ca _fb _db _18
_e3 _2d _e5 _a2 _eb _3f _ff _cf _04 _db _38 _96 _b9 _24 _30 _1b _7a _33 _64 _39
_f2 _e5 _49 _93 _d0 _41 _06 _d9 _4d _09 _80 _ba _98 _01 _22 _79 _a9 _ae _48 _af
_8d _d5 _09 _c1 _9a _8d _29 _4f _37 _90 _4c _19 _1a _93 _30 _1e _cf _da _7a _ef
_5c _54 _c0 _7c _d3 _c0 _4a _2c _32 _2b _15 _60 _5f _85 _f7 _ff _32 _76 _ec _ea
_fa _61 _45 _01 _c5 _c7 _c1 _12 _c9 _d4 _40 _0c _10 _d8 _3a _87 _c6 _ad _1e _b1
_6a _d3 _4d _1a _78 _4f _ab _70 _92 _5d _f8 _c3 _47 _6e _9e _23 _c3 _9d _d8 _a4
_39 _21 _84 _22 _d8 _13 _74 _00 _e3 _fb _52 _1c _e7 _d5 _f0 _63 _30 _16 _80 _d8
_7b _f9 _8d _df _55 _e0 _07 _2b _98 _cb _66 _d7 _94 _0a _c9 _49 _eb _f4 _cf _7c
_e5 _de _bd _a4 _4e _74 _a2 _c9 _c5 _5b _48 _18 _d4 _ff _84 _1b _3e _f5 _ec _98
_1b _e2 _89 _9c _c2 _19 _93 _07 _f6 _75 _c0 _5b _49 _f6 _81 _68 _18 _c2 _2b _db
_23 _14 _de _b5 _e7 _1e _58 _75 _da _3a _a5 _a8 _fe _12 _3d _8e _e0 _3e _76 _c7
_d3 _f8 _09 _d9 _da _58 _f1 _cc _44 _0e _20 _00 _00 _00 _00 _ff _ff _ff _ff _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _04
_00 _00 _00 _00 _00 _00 _00 _03 _00 _00 _00 _00 _00 _00 _00 _fd _ff _ff _ff _ff
_ff _ff _ff _1b _ff _ff _ff _ff _ff _ff _ff _c5 _06 _73 _62 _4a _6c _b1 _7c _1c
_6c _2a _4e _69 _06 _f4 _7a _17 _0c _46 _29 _b8 _72 _37 _81 _d1 _01 _7e _f3 _76
_f1 _a7 _5d _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00
_00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _00 _e6 _85 _3e _72 _59 _fc _1c _2c _24
_90 _a6 _a1 _96 _61 _d0 _80 _69 _eb _8b _f9 _f7 _3e _ac _73 _9f _c9 _67 _78 _99
_e4 _b0 _90 _8b _ec _d2 _a7 _57 _6a _40 _79 _72 _83 _68 _8f _8f _21 _33 _75 _a9
_e0 _d6 _6d _8d _1e _05 _f1 _02 _bc _70 _76 _cd _ba _22 _7b _46 _87 _0e _42 _eb
_5b _b4 _85 _2b _3b _8f _7e _3e _e5 _2f _47 _19 _c5 _b4 _b9 _ab _cb _76 _0f _bf
_12 _56 _46 _70 _7b _32 _e6 _7a _1a _79 _8f _b6 _5e _cf _0b _d4 _ca _8e _fe _50
_6d _e3 _76 _08 _87 _1a _cc _f6 _7c _ed _a9 _a8 _52 _70 _cb _c4 _e7 _c3 _d4 _bd
_6e _db _5f _4e _74 _68 _c1 _e0 _11 _8d _6d _ae _97 _22 _ed _5f _85 _2b _7e _f8
_54 _bf _5d _5d _c1 _ff _4e _06 _e3 _77 _20 _1e _6f _67 _28 _57 _fc _8c _db _9c
_ce _21 _f9 _1c _d3 _22 _bc _71 _88 _a4 _41 _a0 _d1 _0b _86 _9a _65 _28 _2e _e2
_7a _37 _31 _24 _26 _49 _ef _0c _75 _01 _26 _34 _8c _91 _b9 _39 _d9 _2f _c2 _bb
_45 _56 _43 _06 _d0 _04 _e0 _59 _f2 _11 _6f _35 _d7 _96 _b4 _5a _7c _35 _1a _58
_de _a4 _76 _9d _54 _f2 _01 _74 _73 _7e _61 _10 _59 _4c _99 _f6 _90 _a6 _ef _f7
_57 _7b _03 _2a _ce _38 _5a _8e _0f _d7 _1e _42 _5e _95 _36 _b3 _47 _81 _a1 _c6
_dd _e9 _05 _2d _80 _5e _51 _d3 _19 _39 _70 _fc _a9 _26 _9a _fd _dc _b7 _89 _0b
_a0 _d0 _a1 _c6 _6f _94 _9f _70 _cf _8c _97 _a4 _2d _82 _cd _ef _71 _21 _c2 _4b
_80 _d5 _5e _33 _13 _28 _3d _e0 _e9 _b1 _0d _56 _e5 _bb _6e _4a _d2 _ee _bd _8a
_a2 _61 _d1 _40 _b3 _bc _20 _4c _9b _1f _62 _25 _f1 _ef _8a _9e _b6 _59 _71 _35
_69 _95 _14 _f0 _6a _91 _47 _3f _57 _4b _e4 _76 _2c _a3 _57 _e8 _bc _c0 _d2 _46
_99 _f1 _a3 _46 _ed _90 _b3 _3f _3d _41 _ce _4a _5f _e3 _05 _01 _87 _9b _63 _81
_7d _ae _48 _95 _9c _24 _94 _6c _3f _82 _22 _4c _10 _0e _c8 _cf _da _7b _70 _62
_1e _f5 _87 _36 _dd _ad _41 _77 _05 _20 _65 _f2 _3f _0d _28 _35 _fb _42 _d7 _8d
_54 _7c _09 _d2 _b9 _4c _b0 _ac _0f _2a _51 _14 _ef _3a _29 _b0 _39 _62 _f4 _65
_ae _46 _a1 _7e _4c _a7 _25 _08 _d7 _1e _cf _c2 _4e _34 _67 _71 _28 _f5 _3c _15
_1e _05 _75 _48 _ce _18 _0f _3b _3d _fd _c6 _2c _1b _af _d8 _33 _f2 _9c _c6 _b2
_c3 _ec _25 _f0 _98 _01 _b0 _9e _5a _8f _02 _55 _7c _09 _29 _67 _1a _7b _64 _d6
_a7 _df _fa _57 _0c _f5 _b8 _fb _1d _ee _59 _8f _a7 _05 _0b _e2 _9d _6a _9c _58
_c7 _4c _1c _98 _d0 _c4 _1b _49 _40 _16 _ee _d7 _e5 _f5 _44 _25 _3e _70 _ac _09
_c0 _31 _1d _57 _4c _a8 _61 _e4 _c7 _32 _bf _ab _9d _39 _e0 _7c _ce _2c _f2 _ed
_4f _9a _f0 _95 _72 _d1 _d8 _12 _a7 _d9 _25 _d0 _1d _d2 _0c _a1 _4b _2b _63 _92
_53 _f7 _61 _ad _f5 _c3 _7e _d5 _d7 _f0 _69 _e0 _af _8f _2e _7f _12 _ad _55 _27
_5a _50 _69 _9a _5d _6b _a8 _be _d6 _14 _21 _57 _72 _83 _48 _cb _fe _80 _90 _f7
_f5 _e6 _93 _4b _0c _de _ed _ff _d0 _77 _a4 _c3 _b2 _36 _50 _6a _79 _23 _63 _ac
_77 _bb _39 _39 _4a _1a _7c _e9 _9b _29 _eb _b2 _1a _32 _6a _bc _39 _95 _84 _04
_a2 _05 _22 _05 _5b _d9 _63 _be _be _f4 _2c _ab _8e _de _be _fe _db _6b _66 _f7
_b0 _c0 _0c _29 _58 _09 _b0 _33 _e6 _bb _57 _d0 _5f _0a _69 _b7 _93 _3d _72 _1f
_6b _eb _94 _6f _6f _41 _ef _42 _16 _82 _2f _5e _a5 _e8 _57 _bb _3b _64 _e7 _64
_79 _81 _bb _8f _b5 _f7 _b0 _d1 _6b _2b _7e _56 _af _f8 _58 _02 _c5 _5c _09 _eb
_fc _b5 _c0 _c3 _90 _fa _2d _c5 _9e _d6 _b6 _af _d1 _bd _84 _1d _3c _e9 _04);

	let matches = args_desc().get_matches_from(&["ARG0","-x", "3/0xe4", "--date", "20160109", "--in-hash", "-k", "KEY", "c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d", "OUTPUT"]);

	// Braces necessary for now, see https://github.com/rust-lang/rust/issues/31234
	let key=RsaPrivateKey::new(&mut {KEY}).unwrap();

	let sig=do_sign(&matches,&key);

	assert_eq!(&unsafe{std::mem::transmute::<_,[u8;1808]>(sig)}[..],SIGSTRUCT);
}
