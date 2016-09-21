/*
 * The Rust SGXS library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

use abi::*;

use std::io::{self,Read,Write,Result as IoResult,Error as IoError,ErrorKind as IoErrorKind};

#[derive(Debug)]
pub enum Error {
	IoError(IoError),
	StreamNotCanonical,
	InvalidMeasTag,
	InvalidPageOffset,
}

impl From<IoError> for Error {
	fn from(err: IoError) -> Error {
		Error::IoError(err)
	}
}

pub type Result<T> = ::std::result::Result<T, Error>;

// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub enum Meas {
	ECreate(MeasECreate),
	EAdd(MeasEAdd),
	EExtend { header: MeasEExtend, data: [u8;256] },
	BareEExtend(MeasEExtend),
}

impl ::std::fmt::Debug for Meas {
	fn fmt(&self, __arg_0: &mut ::std::fmt::Formatter)
	 -> ::std::fmt::Result {
		match (&*self,) {
			(&Meas::ECreate(ref __self_0),) => {
				let mut builder = __arg_0.debug_tuple("ECreate");
				builder.field(&&(*__self_0));
				builder.finish()
			}
			(&Meas::EAdd(ref __self_0),) => {
				let mut builder = __arg_0.debug_tuple("EAdd");
				builder.field(&&(*__self_0));
				builder.finish()
			}
			(&Meas::EExtend { header: ref __self_0, data: ref __self_1 },)
			=> {
				let mut builder = __arg_0.debug_struct("EExtend");
				builder.field("header", &&(*__self_0));
				builder.field("data", &"<blob>");
				builder.finish()
			}
			(&Meas::BareEExtend(ref __self_0),)
			=> {
				let mut builder = __arg_0.debug_tuple("EExtend");
				builder.field(&&(*__self_0));
				builder.finish()
			}
		}
	}
}

fn read_fill<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> IoResult<bool> {
	let mut read_any = false;
	while !buf.is_empty() {
		match reader.read(buf) {
			Ok(0) => break,
			Ok(n) => { read_any = true; let tmp = buf; buf = &mut tmp[n..]; }
			Err(ref e) if e.kind() == IoErrorKind::Interrupted => {}
			Err(e) => return Err(e),
		}
	}
	if read_any {
		if !buf.is_empty() {
			Err(IoError::new(IoErrorKind::UnexpectedEof,
						   "failed to fill whole buffer"))
		} else {
			Ok(true)
		}
	} else {
		Ok(false)
	}
}

pub trait SgxsRead {
	fn read_meas(&mut self) -> Result<Option<Meas>>;
}

impl<R: Read> SgxsRead for R {
	fn read_meas(&mut self) -> Result<Option<Meas>> {
		use byteorder::{LittleEndian,ReadBytesExt};

		let mut header=[0u8;64];
		if !try!(read_fill(self,&mut header)) {
			return Ok(None);
		}
		let mut headerp=&header[..];

		match headerp.read_u64::<LittleEndian>().unwrap() {
			MEAS_ECREATE => Ok(Some(Meas::ECreate(unsafe{&*(headerp as *const _ as *const MeasECreate)}.clone()))),
			MEAS_EADD    => Ok(Some(Meas::EAdd(unsafe{&*(headerp as *const _ as *const MeasEAdd)}.clone()))),
			MEAS_EEXTEND => {
				let header=unsafe{&*(headerp as *const _ as *const MeasEExtend)}.clone();

				let mut data=[0u8;256];
				if !try!(read_fill(self,&mut data)) {
					return Err(Error::IoError(IoError::new(IoErrorKind::UnexpectedEof,
						   "failed to fill whole buffer")));
				}

				Ok(Some(Meas::EExtend{header:header,data:data}))
			},
			_ => Err(Error::InvalidMeasTag),
		}
	}
}

#[derive(Copy,Clone,PartialEq,Eq,Debug)]
pub struct PageChunks(pub u16);

impl ::std::fmt::Display for PageChunks {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		f.pad(match self.0 {
			0xffff => "all",
			0 => "none",
			_ => "partial",
		})
	}
}

/// The `CanonicalSgxsReader` struct adds canonicalness checking to any `SgxsRead` reader.
///
/// An SGXS stream is canonical if
/// - the first measurement blob is an ECREATE blob, and no other blobs are an ECREATE blob
/// - the offset of every EADD blob does not have the lower 12 bits set
/// - the offset of every EADD blob is higher than that of any previous EADD blob
/// - the offset of every EEXTEND blob does not have the lower 12 bits set
/// - the upper 52 bits of offsets of all EEXTEND blobs are equal to those of the preceding EADD blob
/// - the lower 12 bits of offsets of all consecutive EEXTEND blobs are unique
pub struct CanonicalSgxsReader<'a, R: SgxsRead + 'a> {
	reader: &'a mut R,
	got_ecreate: bool,
	last_offset: Option<u64>,
	chunks_measured: PageChunks,
}

impl<'a, R: SgxsRead + 'a> CanonicalSgxsReader<'a,R> {
	pub fn new(reader: &'a mut R) -> Self {
		CanonicalSgxsReader {
			reader: reader,
			got_ecreate: false,
			last_offset: None,
			chunks_measured: PageChunks(0),
		}
	}

	fn check_chunk_offset(&mut self, offset: u64) -> bool {
		if (offset&0xff)!=0 { return false }
		if let Some(last_offset)=self.last_offset {
			if offset<last_offset { return false }
			let chunk=(offset-last_offset)>>8;
			if chunk>=16 { return false }
			let chunk_bit=1<<chunk;
			if self.chunks_measured.0&chunk_bit == 1 { return false }
			self.chunks_measured.0|=chunk_bit;
			return true;
		}
		return false;
	}
}

impl<'a, R: SgxsRead + 'a> SgxsRead for CanonicalSgxsReader<'a,R> {
	fn read_meas(&mut self) -> Result<Option<Meas>> {
		let meas=try!(self.reader.read_meas());

		match meas {
			Some(Meas::ECreate(_)) => {
				if self.got_ecreate { return Err(Error::StreamNotCanonical) }
				self.got_ecreate=true
			},
			Some(Meas::EAdd(ref header)) => {
				if !self.got_ecreate || (header.offset&0xfff)!=0 || self.last_offset.map_or(false,|lo|header.offset<=lo) {
					return Err(Error::StreamNotCanonical)
				}
				self.last_offset=Some(header.offset);
				self.chunks_measured.0=0;
			},
			Some(Meas::EExtend{ref header,..}) => {
				if !self.got_ecreate || !self.check_chunk_offset(header.offset) {
					return Err(Error::StreamNotCanonical)
				}
			},
			Some(Meas::BareEExtend(_)) => unreachable!(),
			None => {},
		}

		Ok(meas)
	}
}

pub struct PageReader<'a, R: SgxsRead + 'a> {
	reader: CanonicalSgxsReader<'a,R>,
	last_eadd: Option<MeasEAdd>,
}

impl<'a, R: SgxsRead + 'a> PageReader<'a,R> {
	pub fn new(reader: &'a mut R) -> Result<(MeasECreate,Self)> {
		let mut cread=CanonicalSgxsReader::new(reader);
		match try!(cread.read_meas()) {
			Some(Meas::ECreate(header)) => Ok((header,PageReader{reader:cread,last_eadd:None})),
			_ => Err(Error::StreamNotCanonical)
		}
	}

	pub fn read_page(&mut self) -> Result<Option<(MeasEAdd,PageChunks,[u8;4096])>> {
		use std::mem::replace;

		let mut page=[0u8;4096];
		loop {
			let chunks_measured=self.reader.chunks_measured;
			let meas=try!(self.reader.read_meas());
			match meas {
				meas @ Some(Meas::EAdd(_)) | meas @ None => {
					let meas=match meas {
						Some(Meas::EAdd(header)) => Some(header),
						None => None,
						_ => unreachable!()
					};
					if let Some(eadd)=replace(&mut self.last_eadd,meas) {
						return Ok(Some((eadd,chunks_measured,page)));
					} else if self.last_eadd.is_none() {
						return Ok(None);
					}
				},
				Some(Meas::EExtend{header,data}) => {
					let offset=(header.offset&0xfff) as usize;
					(&mut page[offset..offset+256]).write(&data).unwrap();
				},
				_ => { return Err(Error::StreamNotCanonical) },
			}
		}
	}
}

pub type MeasuredData<'a,R>=Option<&'a mut R>;

pub trait SgxsWrite {
	fn write_meas(&mut self, meas: &Meas) -> Result<()>;
	fn write_page<R: Read>(&mut self, data: MeasuredData<R>, offset: u64, secinfo: SecinfoTruncated) -> Result<()>;
	fn write_pages<R: Read>(&mut self, data: MeasuredData<R>, n: usize, offset: u64, secinfo: SecinfoTruncated) -> Result<()>;
}

impl<W: Write> SgxsWrite for W {
	fn write_meas(&mut self, meas: &Meas) -> Result<()> {
		use std::ptr;
		use self::Meas::*;

		let mut buf=[0u8;64];
		unsafe {
			let (tag,headerdst)=buf.split_at_mut(8);
			let tag=&mut*(&mut tag[0] as *mut _ as *mut u64);
			let headerdst=&mut headerdst[0] as *mut _;

			match meas {
				&ECreate(ref header) => { *tag=MEAS_ECREATE; ptr::write(headerdst as *mut _,header.clone()) },
				&EAdd(ref header) => { *tag=MEAS_EADD; ptr::write(headerdst as *mut _,header.clone()) },
				&EExtend{ref header,..} | &BareEExtend(ref header)  => { *tag=MEAS_EEXTEND; ptr::write(headerdst as *mut _,header.clone()) },
			};
		}
		try!(self.write_all(&buf));

		if let &EExtend{ref data,..}=meas {
			try!(self.write_all(data));
		}

		Ok(())
	}

	fn write_page<R: Read>(&mut self, data: MeasuredData<R>, offset: u64, secinfo: SecinfoTruncated) -> Result<()> {
		try!(self.write_meas(&Meas::EAdd(MeasEAdd{offset:offset,secinfo:secinfo})));

		if let Some(reader)=data {
			let mut reader=reader.chain(io::repeat(0));
			for i in 0..16 {
				try!(self.write_meas(&Meas::BareEExtend(MeasEExtend{offset:offset+(i*256)})));
				try!(io::copy(&mut (&mut reader).take(256),self));
			}
		}

		Ok(())
	}

	fn write_pages<R: Read>(&mut self, mut data: MeasuredData<R>, n: usize, offset: u64, secinfo: SecinfoTruncated) -> Result<()> {
		for i in 0..(n as u64) {
			try!(self.write_page(data.as_mut(),offset+4096*i,secinfo.clone()));
		}
		Ok(())
	}
}

pub struct CanonicalSgxsWriter<'a, W: SgxsWrite + 'a> {
	writer: &'a mut W,
	next_offset: u64,
}

impl<'a, W: SgxsWrite + 'a> CanonicalSgxsWriter<'a,W> {
	pub fn new(mut writer: &'a mut W, ecreate: MeasECreate) -> Result<Self> {
		try!(writer.write_meas(&Meas::ECreate(ecreate)));
		Ok(CanonicalSgxsWriter {
			writer: writer,
			next_offset: 0,
		})
	}

	/// If offset is None, just append at the current offset.
	pub fn write_page<R: Read>(&mut self, data: MeasuredData<R>, offset: Option<u64>, secinfo: SecinfoTruncated) -> Result<()> {
		self.write_pages(data,1,offset,secinfo)
	}

	/// If offset is None, just append at the current offset.
	pub fn write_pages<R: Read>(&mut self, data: MeasuredData<R>, n: usize, offset: Option<u64>, secinfo: SecinfoTruncated) -> Result<()> {
		match offset {
			Some(offset) if offset&0xfff!=0 => { return Err(Error::InvalidPageOffset) },
			Some(offset) if offset<self.next_offset => { return Err(Error::StreamNotCanonical) },
			Some(offset) => { self.next_offset=offset }
			None => {}
		}
		try!(self.writer.write_pages(data,n,self.next_offset,secinfo));
		self.skip_pages(n);
		Ok(())
	}

	pub fn skip_page(&mut self) {
		self.skip_pages(1);
	}

	pub fn skip_pages(&mut self, n: usize) {
		self.next_offset+=(n as u64)*4096;
	}

	pub fn offset(&self) -> u64 {
		self.next_offset
	}
}

/// Note: only the first 48 bytes of the `Secinfo` structure are included in a
/// `Meas` blob.
#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct SecinfoTruncated {
	pub flags: SecinfoFlags,
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct MeasECreate {
	pub ssaframesize: u32,
	pub size: u64,
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct MeasEAdd {
	pub offset: u64,
	pub secinfo: SecinfoTruncated,
}

#[repr(C,packed)]
#[derive(Clone,Debug,Default)]
pub struct MeasEExtend {
	pub offset: u64,
}
