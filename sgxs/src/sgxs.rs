/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use abi::*;

use std::io::{self, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use std::result::Result as StdResult;

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "The stream is not canonical.")]
    StreamNotCanonical,
    #[fail(display = "An invalid measurement tag {:016x} was encountered.", _0)]
    InvalidMeasTag(u64),
    #[fail(display = "The given offset is not a multiple of the page size.")]
    InvalidPageOffset,
    #[fail(display = "An unsized stream was encountered but a sized stream was expected.")]
    StreamUnsized,
}

pub type Result<T> = StdResult<T, ::failure::Error>;

// Doesn't work because large array: #[derive(Clone,Debug,Default)]
pub enum Meas {
    ECreate(MeasECreate),
    EAdd(MeasEAdd),
    EExtend {
        header: MeasEExtend,
        data: [u8; 256],
    },
    BareEExtend(MeasEExtend),
    /// The start of an SGXS file with an unknown enclave size which can be
    /// filled in later. The `size` member is an offset of where to write the
    /// enclave size as a 64-bit unsigned little endian integer, in addition to
    /// the `size` member itself of course.
    Unsized(MeasECreate),
    /// A 256-byte chunk of memory that should be loaded but not measured.
    Unmeasured {
        header: MeasEExtend,
        data: [u8; 256],
    },
    BareUnmeasured(MeasEExtend),
}

pub const MEAS_UNSIZED: u64 = 0x0044455a49534e55;
pub const MEAS_UNMEASRD: u64 = 0x44525341454d4e55;

impl ::std::fmt::Debug for Meas {
    fn fmt(&self, __arg_0: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
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
            (&Meas::EExtend {
                header: ref __self_0,
                data: ref __self_1,
            },) => {
                let mut builder = __arg_0.debug_struct("EExtend");
                builder.field("header", &&(*__self_0));
                builder.field("data", &"<blob>");
                builder.finish()
            }
            (&Meas::BareEExtend(ref __self_0),) => {
                let mut builder = __arg_0.debug_tuple("EExtend");
                builder.field(&&(*__self_0));
                builder.finish()
            }
            (&Meas::Unsized(ref __self_0),) => {
                let mut builder = __arg_0.debug_tuple("Unsized");
                builder.field(&&(*__self_0));
                builder.finish()
            }
            (&Meas::Unmeasured {
                header: ref __self_0,
                data: ref __self_1,
            },) => {
                let mut builder = __arg_0.debug_struct("Unmeasured");
                builder.field("header", &&(*__self_0));
                builder.field("data", &"<blob>");
                builder.finish()
            }
            (&Meas::BareUnmeasured(ref __self_0),) => {
                let mut builder = __arg_0.debug_tuple("Unmeasured");
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
            Ok(n) => {
                read_any = true;
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(ref e) if e.kind() == IoErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if read_any {
        if !buf.is_empty() {
            Err(IoError::new(
                IoErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))
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
        use byteorder::{LittleEndian, ReadBytesExt};

        let mut header = [0u8; 64];
        if !try!(read_fill(self, &mut header)) {
            return Ok(None);
        }
        let mut headerp = &header[..];

        match headerp.read_u64::<LittleEndian>().unwrap() {
            MEAS_ECREATE => Ok(Some(Meas::ECreate(
                unsafe { &*(headerp as *const _ as *const MeasECreate) }.clone(),
            ))),
            MEAS_UNSIZED => Ok(Some(Meas::Unsized(
                unsafe { &*(headerp as *const _ as *const MeasECreate) }.clone(),
            ))),
            MEAS_EADD => Ok(Some(Meas::EAdd(
                unsafe { &*(headerp as *const _ as *const MeasEAdd) }.clone(),
            ))),
            m @ MEAS_EEXTEND | m @ MEAS_UNMEASRD => {
                let header = unsafe { &*(headerp as *const _ as *const MeasEExtend) }.clone();

                let mut data = [0u8; 256];
                if !try!(read_fill(self, &mut data)) {
                    return Err(IoError::new(
                        IoErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    )
                    .into());
                }

                if m == MEAS_EEXTEND {
                    Ok(Some(Meas::EExtend {
                        header: header,
                        data: data,
                    }))
                } else {
                    Ok(Some(Meas::Unmeasured {
                        header: header,
                        data: data,
                    }))
                }
            }
            v => Err(Error::InvalidMeasTag(v).into()),
        }
    }
}

impl SgxsRead for &mut dyn SgxsRead {
    fn read_meas(&mut self) -> Result<Option<Meas>> {
        (*self).read_meas()
    }
}

// TODO: update to [PageChunk; 16]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
    chunks_seen: PageChunks,
}

impl<'a, R: SgxsRead + 'a> CanonicalSgxsReader<'a, R> {
    pub fn new(reader: &'a mut R) -> Self {
        CanonicalSgxsReader {
            reader: reader,
            got_ecreate: false,
            last_offset: None,
            chunks_measured: PageChunks(0),
            chunks_seen: PageChunks(0),
        }
    }

    fn check_chunk_offset(&mut self, offset: u64, measured: bool) -> bool {
        if (offset & 0xff) != 0 {
            return false;
        }
        if let Some(last_offset) = self.last_offset {
            if offset < last_offset {
                return false;
            }
            let chunk = (offset - last_offset) >> 8;
            if chunk >= 16 {
                return false;
            }
            let chunk_bit = 1 << chunk;
            if self.chunks_seen.0 & chunk_bit == 1 {
                return false;
            }
            self.chunks_seen.0 |= chunk_bit;
            if measured {
                self.chunks_measured.0 |= chunk_bit;
            }
            return true;
        }
        return false;
    }
}

impl<'a, R: SgxsRead + 'a> SgxsRead for CanonicalSgxsReader<'a, R> {
    fn read_meas(&mut self) -> Result<Option<Meas>> {
        let meas = try!(self.reader.read_meas());

        match meas {
            Some(Meas::ECreate(_)) | Some(Meas::Unsized(_)) => {
                if self.got_ecreate {
                    return Err(Error::StreamNotCanonical.into());
                }
                self.got_ecreate = true
            }
            Some(Meas::EAdd(ref header)) => {
                if !self.got_ecreate
                    || (header.offset & 0xfff) != 0
                    || self.last_offset.map_or(false, |lo| header.offset <= lo)
                {
                    return Err(Error::StreamNotCanonical.into());
                }
                self.last_offset = Some(header.offset);
                self.chunks_measured.0 = 0;
                self.chunks_seen.0 = 0;
            }
            Some(Meas::EExtend { ref header, .. }) => {
                if !self.got_ecreate || !self.check_chunk_offset(header.offset, true) {
                    return Err(Error::StreamNotCanonical.into());
                }
            }
            Some(Meas::Unmeasured { ref header, .. }) => {
                if !self.got_ecreate || !self.check_chunk_offset(header.offset, false) {
                    return Err(Error::StreamNotCanonical.into());
                }
            }
            Some(Meas::BareEExtend(_)) | Some(Meas::BareUnmeasured(_)) => unreachable!(),
            None => {}
        }

        Ok(meas)
    }
}

pub struct PageReader<'a, R: SgxsRead + 'a> {
    reader: CanonicalSgxsReader<'a, R>,
    last_eadd: Option<MeasEAdd>,
}

pub struct CreateInfo {
    pub ecreate: MeasECreate,
    pub sized: bool,
}

impl<'a, R: SgxsRead + 'a> PageReader<'a, R> {
    pub fn new(reader: &'a mut R) -> Result<(CreateInfo, Self)> {
        let mut cread = CanonicalSgxsReader::new(reader);
        let cinfo = match try!(cread.read_meas()) {
            Some(Meas::ECreate(ecreate)) => CreateInfo {
                ecreate,
                sized: true,
            },
            Some(Meas::Unsized(ecreate)) => CreateInfo {
                ecreate,
                sized: false,
            },
            _ => return Err(Error::StreamNotCanonical.into()),
        };
        Ok((
            cinfo,
            PageReader {
                reader: cread,
                last_eadd: None,
            },
        ))
    }

    pub fn read_page(&mut self) -> Result<Option<(MeasEAdd, PageChunks, [u8; 4096])>> {
        use std::mem::replace;

        let mut page = [0u8; 4096];
        loop {
            let chunks_measured = self.reader.chunks_measured;
            let meas = try!(self.reader.read_meas());
            match meas {
                meas @ Some(Meas::EAdd(_)) | meas @ None => {
                    let meas = match meas {
                        Some(Meas::EAdd(header)) => Some(header),
                        None => None,
                        _ => unreachable!(),
                    };
                    if let Some(eadd) = replace(&mut self.last_eadd, meas) {
                        return Ok(Some((eadd, chunks_measured, page)));
                    } else if self.last_eadd.is_none() {
                        return Ok(None);
                    }
                }
                Some(Meas::EExtend { header, data }) | Some(Meas::Unmeasured { header, data }) => {
                    let offset = (header.offset & 0xfff) as usize;
                    (&mut page[offset..offset + 256]).write(&data).unwrap();
                }
                _ => return Err(Error::StreamNotCanonical.into()),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageChunk {
    Skipped,
    Included,
    IncludedMeasured,
}

pub struct MeasuredData<'a, R: Read + 'a> {
    chunks: [PageChunk; 16],
    reader: Option<&'a mut R>,
}

impl<'a, R: Read + 'a> From<Option<&'a mut R>> for MeasuredData<'a, R> {
    fn from(reader: Option<&'a mut R>) -> Self {
        use self::PageChunk::*;
        MeasuredData {
            chunks: [if reader.is_some() {
                IncludedMeasured
            } else {
                Skipped
            }; 16],
            reader,
        }
    }
}

impl<'a, R: Read + 'a> From<(&'a mut R, [PageChunk; 16])> for MeasuredData<'a, R> {
    fn from((reader, chunks): (&'a mut R, [PageChunk; 16])) -> Self {
        MeasuredData {
            chunks,
            reader: Some(reader),
        }
    }
}

pub trait SgxsWrite {
    fn write_meas(&mut self, meas: &Meas) -> Result<()>;
    fn write_page<'a, R: Read + 'a, D: Into<MeasuredData<'a, R>>>(
        &mut self,
        data: D,
        offset: u64,
        secinfo: SecinfoTruncated,
    ) -> Result<()>;
    fn write_pages<R: Read>(
        &mut self,
        data: Option<&mut R>,
        n: usize,
        offset: u64,
        secinfo: SecinfoTruncated,
    ) -> Result<()>;
}

impl<W: Write> SgxsWrite for W {
    fn write_meas(&mut self, meas: &Meas) -> Result<()> {
        use self::Meas::*;
        use std::ptr;

        let mut buf = [0u8; 64];
        unsafe {
            let (tag, headerdst) = buf.split_at_mut(8);
            let tag = &mut *(&mut tag[0] as *mut _ as *mut u64);
            let headerdst = &mut headerdst[0] as *mut _;

            match meas {
                &ECreate(ref header) => {
                    *tag = MEAS_ECREATE;
                    ptr::write(headerdst as *mut _, header.clone())
                }
                &Unsized(ref header) => {
                    *tag = MEAS_UNSIZED;
                    ptr::write(headerdst as *mut _, header.clone())
                }
                &EAdd(ref header) => {
                    *tag = MEAS_EADD;
                    ptr::write(headerdst as *mut _, header.clone())
                }
                &EExtend { ref header, .. } | &BareEExtend(ref header) => {
                    *tag = MEAS_EEXTEND;
                    ptr::write(headerdst as *mut _, header.clone())
                }
                &Unmeasured { ref header, .. } | &BareUnmeasured(ref header) => {
                    *tag = MEAS_UNMEASRD;
                    ptr::write(headerdst as *mut _, header.clone())
                }
            };
        }
        try!(self.write_all(&buf));

        match meas {
            &EExtend { ref data, .. } | &Unmeasured { ref data, .. } => try!(self.write_all(data)),
            _ => {}
        }

        Ok(())
    }

    fn write_page<'a, R: Read + 'a, D: Into<MeasuredData<'a, R>>>(
        &mut self,
        data: D,
        offset: u64,
        secinfo: SecinfoTruncated,
    ) -> Result<()> {
        try!(self.write_meas(&Meas::EAdd(MeasEAdd {
            offset: offset,
            secinfo: secinfo
        })));

        let MeasuredData { chunks, reader } = data.into();
        let mut reader = reader.map(|r| r.chain(io::repeat(0)));
        for (i, chunk) in chunks.into_iter().enumerate() {
            let eext = MeasEExtend {
                offset: offset + (i as u64 * 256),
            };
            match *chunk {
                PageChunk::Skipped => continue,
                PageChunk::Included => try!(self.write_meas(&Meas::BareUnmeasured(eext))),
                PageChunk::IncludedMeasured => try!(self.write_meas(&Meas::BareEExtend(eext))),
            }
            try!(io::copy(&mut reader.as_mut().unwrap().take(256), self));
        }

        Ok(())
    }

    fn write_pages<R: Read>(
        &mut self,
        mut data: Option<&mut R>,
        n: usize,
        offset: u64,
        secinfo: SecinfoTruncated,
    ) -> Result<()> {
        for i in 0..(n as u64) {
            try!(self.write_page(data.as_mut(), offset + 4096 * i, secinfo.clone()));
        }
        Ok(())
    }
}

pub struct CanonicalSgxsWriter<'a, W: SgxsWrite + 'a> {
    writer: &'a mut W,
    next_offset: u64,
}

impl<'a, W: SgxsWrite + 'a> CanonicalSgxsWriter<'a, W> {
    pub fn new(writer: &'a mut W, ecreate: MeasECreate, sized: bool) -> Result<Self> {
        if sized {
            try!(writer.write_meas(&Meas::ECreate(ecreate)));
        } else {
            try!(writer.write_meas(&Meas::Unsized(ecreate)));
        }
        Ok(CanonicalSgxsWriter {
            writer: writer,
            next_offset: 0,
        })
    }

    fn check_offset(&mut self, offset: Option<u64>) -> Result<()> {
        match offset {
            Some(offset) if offset & 0xfff != 0 => return Err(Error::InvalidPageOffset.into()),
            Some(offset) if offset < self.next_offset => {
                return Err(Error::StreamNotCanonical.into())
            }
            Some(offset) => self.next_offset = offset,
            None => {}
        }
        Ok(())
    }

    /// If offset is None, just append at the current offset.
    pub fn write_page<'b, R: Read + 'b, D: Into<MeasuredData<'b, R>>>(
        &mut self,
        data: D,
        offset: Option<u64>,
        secinfo: SecinfoTruncated,
    ) -> Result<()> {
        self.check_offset(offset)?;
        try!(self.writer.write_page(data, self.next_offset, secinfo));
        self.skip_page();
        Ok(())
    }

    /// If offset is None, just append at the current offset.
    pub fn write_pages<R: Read>(
        &mut self,
        data: Option<&mut R>,
        n: usize,
        offset: Option<u64>,
        secinfo: SecinfoTruncated,
    ) -> Result<()> {
        self.check_offset(offset)?;
        try!(self.writer.write_pages(data, n, self.next_offset, secinfo));
        self.skip_pages(n);
        Ok(())
    }

    pub fn skip_page(&mut self) {
        self.skip_pages(1);
    }

    pub fn skip_pages(&mut self, n: usize) {
        self.next_offset += (n as u64) * 4096;
    }

    pub fn offset(&self) -> u64 {
        self.next_offset
    }
}

/// Note: only the first 48 bytes of the `Secinfo` structure are included in a
/// `Meas` blob.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SecinfoTruncated {
    pub flags: SecinfoFlags,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MeasECreate {
    pub ssaframesize: u32,
    pub size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MeasEAdd {
    pub offset: u64,
    pub secinfo: SecinfoTruncated,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MeasEExtend {
    pub offset: u64,
}

/// Copy only the measured bits of an SGXS stream.
///
/// # Example
/// Compute ENCLAVEHASH from an SGXS:
///
/// ```
/// extern crate crypto_hash;
/// extern crate sgxs;
/// use crypto_hash::{Hasher, Algorithm};
/// use sgxs::sgxs::{SgxsRead, Result, copy_measured};
///
/// fn enclavehash<R: SgxsRead>(stream: &mut R) -> Result<[u8; 32]> {
///     let mut hasher = Hasher::new(Algorithm::SHA256);
///     copy_measured(stream, &mut hasher)?;
///     let mut hash = [0u8; 32];
///     hash.copy_from_slice(&hasher.finish());
///     Ok(hash)
/// }
///
/// # fn main() { /* compile test */ }
/// ```
pub fn copy_measured<R: SgxsRead, W: SgxsWrite>(reader: &mut R, writer: &mut W) -> Result<()> {
    while let Some(meas) = reader.read_meas()? {
        match meas {
            Meas::Unsized(_) => return Err(Error::StreamUnsized.into()),
            Meas::Unmeasured { .. } => (),
            meas => writer.write_meas(&meas)?,
        }
    }

    Ok(())
}
