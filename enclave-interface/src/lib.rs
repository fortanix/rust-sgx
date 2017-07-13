/*
 * Interface to interact with libenclave-based secure enclaves.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#![feature(asm)]
extern crate sgx_isa;
extern crate sgxs;

pub mod tcs;
pub mod util;
