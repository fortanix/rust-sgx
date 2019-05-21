/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate clap;
extern crate num;
extern crate openssl;
extern crate regex;
extern crate sgx_isa;
extern crate sgxs;

use std::borrow::Borrow;
use std::fs::File;
use std::io::{Read, Write};

use num::{Num, Unsigned};
use openssl::hash::Hasher;
use openssl::pkey::{self, PKey};
use regex::Regex;

use sgx_isa::{AttributesFlags, MiscSelect, SigStruct};
use sgxs::sigstruct::{self, EnclaveHash, Signer};

fn write_sigstruct(path: &str, sig: SigStruct) {
    File::create(path)
        .expect("Unable to open output file")
        .write_all(sig.as_ref())
        .expect("Unable to write output file");
}

const DATE_REGEX: &'static str = "^[[:digit:]]{8}$";
const NUM_REGEX: &'static str = "^([[:digit:]]+|0x[[:xdigit:]]+)$";
const NUM_NUM_REGEX: &'static str =
    "^([[:digit:]]+|0x[[:xdigit:]]+)(/([[:digit:]]+|0x[[:xdigit:]]+))?$";
const HASH_REGEX: &'static str = "^[[:xdigit:]]{64}$";

fn date_validate(s: String) -> Result<(), String> {
    if Regex::new(DATE_REGEX).unwrap().is_match(&s) {
        Ok(())
    } else {
        Err(String::from("date must be specified as YYYYMMDD"))
    }
}

fn num_validate(s: String) -> Result<(), String> {
    if Regex::new(NUM_REGEX).unwrap().is_match(&s) {
        Ok(())
    } else {
        Err(String::from("the value must be numeric"))
    }
}

fn num_num_validate(s: String) -> Result<(), String> {
    if Regex::new(NUM_NUM_REGEX).unwrap().is_match(&s) {
        Ok(())
    } else {
        Err(String::from("the value must be a number or number/number"))
    }
}

fn hash_validate(s: &str) -> Result<(), String> {
    if Regex::new(HASH_REGEX).unwrap().is_match(s) {
        Ok(())
    } else {
        Err(String::from("the hash must be 64 hexadecimal characters"))
    }
}

fn parse_num<T: Copy + Unsigned + Num<FromStrRadixErr = std::num::ParseIntError>>(s: &str) -> T {
    if s.starts_with("0x") {
        Num::from_str_radix(&s[2..], 16).unwrap()
    } else {
        Num::from_str_radix(s, 10).unwrap()
    }
}

fn parse_num_num<T: Copy + Unsigned + Num<FromStrRadixErr = std::num::ParseIntError>>(
    s: &str,
) -> (T, T) {
    let mut splits = s.splitn(2, "/");
    let num1 = parse_num(splits.next().unwrap());
    let num2 = splits.next().map(parse_num).unwrap_or(num1);
    (num1, num2)
}

fn hex_digit_to_num(ascii: u8) -> u8 {
    match ascii {
        b'0'...b'9' => ascii - b'0',
        b'A'...b'F' => ascii - b'A' + 10,
        b'a'...b'f' => ascii - b'a' + 10,
        _ => panic!("Tried to convert non-hex character"),
    }
}

fn parse_hexstr<S: Borrow<str>>(s: S) -> Vec<u8> {
    let s = s.borrow();
    let mut vec = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        vec.push(hex_digit_to_num(chunk[0]) << 4 | hex_digit_to_num(chunk[1]))
    }
    vec
}

fn args_desc<'a>() -> clap::App<'a, 'a> {
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
        .arg(Arg::with_name("verifykey")               .short("V").long("resign-verify").value_name("FILE")                             .help("Verify the output file is a correct signature using the specified PEM-encoded RSA private key"))
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

fn do_sign<'a>(matches: &clap::ArgMatches<'a>, key: &PKey<pkey::Private>) -> SigStruct {
    let enclavehash = if matches.is_present("input-hash") {
        let s = matches.value_of("input").unwrap();
        hash_validate(s).unwrap();
        let mut hash = [0u8; 32];
        (&mut hash[..]).write_all(&parse_hexstr(s)).unwrap();
        EnclaveHash::new(hash)
    } else {
        let mut sgxsfile =
            File::open(matches.value_of("input").unwrap()).expect("Unable to open input SGXS file");
        EnclaveHash::from_stream::<_, Hasher>(&mut sgxsfile)
            .expect("Unable to read input SGXS file")
    };

    let mut signer = Signer::new(enclavehash);

    if let Some((sel, mask)) = matches
        .value_of("miscselect/miscmask")
        .map(parse_num_num::<u32>)
    {
        let sel = MiscSelect::from_bits(sel).unwrap_or_else(|| {
            println!("WARNING: Dropping unknown bits in input MISCSELECT!");
            MiscSelect::from_bits_truncate(sel)
        });
        signer.miscselect(sel, !mask);
    }

    let (mut attributes, attributemask) = matches
        .value_of("attributes/attributemask")
        .map(parse_num_num::<u64>)
        .unwrap_or((
            sgx_isa::AttributesFlags::MODE64BIT.bits(),
            sgx_isa::AttributesFlags::DEBUG.bits(),
        ));
    let mut attributemask = !attributemask;
    if matches.is_present("32bit") {
        attributes &= !(sgx_isa::AttributesFlags::MODE64BIT.bits());
        attributemask |= sgx_isa::AttributesFlags::MODE64BIT.bits();
    }
    if matches.is_present("debug") {
        attributes |= sgx_isa::AttributesFlags::DEBUG.bits();
        attributemask &= !(sgx_isa::AttributesFlags::DEBUG.bits());
    }
    let attributes = AttributesFlags::from_bits(attributes).unwrap_or_else(|| {
        println!("WARNING: Dropping unknown bits in input ATTRIBUTES!");
        AttributesFlags::from_bits_truncate(attributes)
    });
    signer.attributes_flags(attributes, attributemask);

    matches
        .value_of("xfrm/xfrmmask")
        .map(parse_num_num::<u64>)
        .map(|(xfrm, xfrmmask)| signer.attributes_xfrm(xfrm, !xfrmmask));

    matches
        .value_of("swdefined")
        .map(parse_num::<u32>)
        .map(|v| signer.swdefined(v));
    matches
        .value_of("isvprodid")
        .map(parse_num::<u16>)
        .map(|v| signer.isvprodid(v));
    matches
        .value_of("isvsvn")
        .map(parse_num::<u16>)
        .map(|v| signer.isvsvn(v));

    if let Some(date) = matches.value_of("date") {
        signer.date(
            date[0..4].parse::<u16>().unwrap(),
            date[4..6].parse::<u8>().unwrap(),
            date[6..8].parse::<u8>().unwrap(),
        );
    }

    signer
        .sign::<_, Hasher>(&*key.rsa().unwrap())
        .expect("Error during signing operation")
}

fn main() {
    let matches = args_desc().get_matches();

    let mut pem = vec![];
    File::open(matches.value_of("key-file").unwrap())
        .expect("Unable to open input key file")
        .read_to_end(&mut pem)
        .expect("Unable to read input key file");
    let key = PKey::private_key_from_pem(&pem).unwrap();

    let sig = do_sign(&matches, &key);

    if let Some(vrk) = matches.value_of("verifykey") {
        let mut pem = vec![];
        File::open(vrk)
            .expect("Unable to open input verify key file")
            .read_to_end(&mut pem)
            .expect("Unable to read input verify key file");
        let key = PKey::public_key_from_pem(&pem).expect("Unable to read input verify key file");
        let oldsig =
            sigstruct::read(&mut File::open(matches.value_of("output").unwrap()).unwrap()).unwrap();
        if sig.enclavehash != oldsig.enclavehash {
            panic!("ENCLAVEHASH mismatch");
        }
        sigstruct::verify::<_, Hasher>(&oldsig, &*key.rsa().unwrap())
            .expect("Input signature verification failed");
    }

    let enclavehash = sig.enclavehash.clone();

    write_sigstruct(matches.value_of("output").unwrap(), sig);

    println!("ENCLAVEHASH: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} (OK)",enclavehash[0],enclavehash[1],enclavehash[2],enclavehash[3],enclavehash[4],enclavehash[5],enclavehash[6],enclavehash[7],enclavehash[8],enclavehash[9],enclavehash[10],enclavehash[11],enclavehash[12],enclavehash[13],enclavehash[14],enclavehash[15],enclavehash[16],enclavehash[17],enclavehash[18],enclavehash[19],enclavehash[20],enclavehash[21],enclavehash[22],enclavehash[23],enclavehash[24],enclavehash[25],enclavehash[26],enclavehash[27],enclavehash[28],enclavehash[29],enclavehash[30],enclavehash[31]);
}

#[cfg(test)]
#[test]
fn test_sig() {
    static KEY: &'static [u8] = include_bytes!("../../tests/data/sig1.key.pem");
    static SIGSTRUCT: &'static [u8] = include_bytes!("../../tests/data/sig1.sigstruct.bin");

    let matches = args_desc().get_matches_from(&[
        "ARG0",
        "-x",
        "3/0xe4",
        "--date",
        "20160109",
        "--in-hash",
        "-k",
        "KEY",
        "c50673624a6cb17c1c6c2a4e6906f47a170c4629b8723781d1017ef376f1a75d",
        "OUTPUT",
    ]);

    let key = PKey::private_key_from_pem(KEY).unwrap();

    let sig = do_sign(&matches, &key);

    sigstruct::verify::<_, Hasher>(&sig, &*key.rsa().unwrap()).unwrap();

    assert_eq!(
        sig.as_ref(),
        SIGSTRUCT
    );
}
