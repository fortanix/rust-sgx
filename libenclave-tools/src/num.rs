/*
 * Tools for building and linking enclaves using libenclave.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use std::num::ParseIntError;
use std::borrow::Borrow;

pub trait NumArg: Copy {
	fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;

	fn parse_arg<S: Borrow<str>>(s: S) -> Self {
		parse_num(s).unwrap()
	}

	fn validate_arg(s: String) -> Result<(),String> {
		match parse_num::<Self,_>(s) {
			Ok(_) => Ok(()),
			Err(_) => Err(String::from("the value must be numeric")),
		}
	}
}

fn parse_num<T: NumArg, S: Borrow<str>>(s: S) -> Result<T,ParseIntError> {
	let s=s.borrow();
	if s.starts_with("0x") {
		T::from_str_radix(&s[2..],16)
	} else {
		T::from_str_radix(s,10)
	}
}

impl NumArg for u32 {
	fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
		Self::from_str_radix(src,radix)
	}
}

impl NumArg for u64 {
	fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
		Self::from_str_radix(src,radix)
	}
}
