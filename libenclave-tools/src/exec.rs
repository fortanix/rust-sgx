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

use std::process::{Command,Output as ProcessOutput,ExitStatus};
use std::io::Error as IoError;
use std::fmt;

#[derive(Debug)]
pub enum ExecError {
	Io(IoError),
	Status(ExitStatus),
}

impl fmt::Display for ExecError {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			ExecError::Io(ref err) => write!(fmt,"I/O error while executing: {}",err),
			ExecError::Status(ref status) => write!(fmt,"Process exited with {}",status),
		}
	}
}

pub trait CommandExt {
	fn output_ext(self, verbose: bool) -> Result<ProcessOutput,ExecError>;
	fn status_ext(self, verbose: bool) -> Result<(),ExecError>;
}

impl CommandExt for Command {
	fn output_ext(mut self, verbose: bool) -> Result<ProcessOutput,ExecError> {
		if verbose { println!("Executing {:?}",self); }
		match self.output() {
			Err(err) => Err(ExecError::Io(err)),
			Ok(ref out) if !out.status.success() => Err(ExecError::Status(out.status)),
			Ok(out) => Ok(out),
		}
	}

	fn status_ext(mut self, verbose: bool) -> Result<(),ExecError> {
		if verbose { println!("Executing {:?}",self); }
		match self.status() {
			Err(err) => Err(ExecError::Io(err)),
			Ok(status) if !status.success() => Err(ExecError::Status(status)),
			Ok(_) => Ok(()),
		}
	}
}
