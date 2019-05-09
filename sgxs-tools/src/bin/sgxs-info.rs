/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate sgx_isa;
extern crate sgxs as sgxs_crate;

use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::path::Path;

use sgx_isa::{PageType, SecinfoFlags};
use crate::sgxs_crate::sgxs::{self, SgxsRead};
use crate::sgxs_crate::util::size_fit_natural;

/// Ok(Some(_)) all data is _
/// Ok(None) there is data, but not all bytes are the same
/// Err(()) there is no data
#[derive(Debug, PartialEq, Eq)]
enum DataClass {
    Same(u8),
    Different,
    Absent,
}

fn classify_data(data: &[u8]) -> DataClass {
    if data.len() == 0 {
        return DataClass::Absent;
    }
    let first = data[0];
    if data.len() == 1 || data[0..data.len() - 1].iter().eq(data[1..].iter()) {
        DataClass::Same(first)
    } else {
        DataClass::Different
    }
}

impl fmt::Display for DataClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::DataClass::*;
        match *self {
            Same(0) | Absent => f.pad("(empty)"),
            Same(value) => write!(f, "[0x{:02x}]*", value),
            Different => f.pad("(data)"),
        }
    }
}

fn list_all<P: AsRef<Path>>(path: P) -> sgxs::Result<()> {
    let mut file = File::open(path)?;
    loop {
        if let Some(meas) = file.read_meas()? {
            match meas {
                sgxs::Meas::ECreate(ecreate) => {
                    println!("ECREATE size=0x{:x} ssaframesize={}", { ecreate.size }, {
                        ecreate.ssaframesize
                    })
                }
                sgxs::Meas::Unsized(ecreate) => {
                    println!("UNSIZED offset=0x{:x} ssaframesize={}", { ecreate.size }, {
                        ecreate.ssaframesize
                    })
                }
                sgxs::Meas::EAdd(eadd) => println!(
                    "EADD offset=0x{:8x} pagetype={:?} flags={:?}",
                    eadd.offset,
                    eadd.secinfo.flags.page_type(),
                    eadd.secinfo.flags & !SecinfoFlags::PT_MASK
                ),
                sgxs::Meas::EExtend { header, data } => println!(
                    "EEXTEND offset=0x{:8x} data={}",
                    header.offset,
                    classify_data(&data)
                ),
                sgxs::Meas::Unmeasured { header, data } => println!(
                    "UNMEASRD offset=0x{:8x} data={}",
                    header.offset,
                    classify_data(&data)
                ),
                sgxs::Meas::BareEExtend(_) | sgxs::Meas::BareUnmeasured(_) => unreachable!(),
            }
        } else {
            break;
        }
    }
    Ok(())
}

fn list_pages<P: AsRef<Path>>(path: P) -> sgxs::Result<()> {
    let mut file = File::open(path)?;
    let (sgxs::CreateInfo { ecreate, sized }, mut reader) = sgxs::PageReader::new(&mut file)?;
    if sized {
        println!("ECREATE size=0x{:x} ssaframesize={}", { ecreate.size }, {
            ecreate.ssaframesize
        });
    } else {
        println!("UNSIZED offset=0x{:x} ssaframesize={}", { ecreate.size }, {
            ecreate.ssaframesize
        });
    }
    loop {
        if let Some((eadd, chunks, data)) = reader.read_page()? {
            println!(
                "EADD offset=0x{:8x} pagetype={:<4} flags={:<9} data={:>7} measured={}",
                eadd.offset,
                format!("{:?}", eadd.secinfo.flags.page_type()),
                format!("{:?}", eadd.secinfo.flags & !SecinfoFlags::PT_MASK),
                classify_data(&data),
                chunks
            );
        } else {
            break;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum PageCharacteristic {
    Gap,
    Page {
        flags: SecinfoFlags,
        measured_chunks: sgxs::PageChunks,
        data: DataClass,
    },
}

impl fmt::Display for PageCharacteristic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::PageCharacteristic::*;
        match *self {
            Gap => write!(f, "(unmapped)"),
            Page {
                ref flags,
                measured_chunks,
                ref data,
            } => {
                let mut perm = [b'-'; 3];
                if flags.contains(SecinfoFlags::R) {
                    perm[0] = b'r';
                }
                if flags.contains(SecinfoFlags::W) {
                    perm[1] = b'w';
                }
                if flags.contains(SecinfoFlags::X) {
                    perm[2] = b'x';
                }

                write!(
                    f,
                    "{:<4} {} {:>7} meas={}",
                    format!("{:?}", PageType::try_from(flags.page_type()).unwrap()),
                    unsafe { std::str::from_utf8_unchecked(&perm) },
                    data,
                    measured_chunks
                )
            }
        }
    }
}

struct Pages<'a, R: sgxs::SgxsRead + 'a> {
    reader: sgxs::PageReader<'a, R>,
    last_offset: Option<u64>,
    last_read_page: Option<(u64, PageCharacteristic)>,
    size: Option<u64>,
}

impl<'a, R: sgxs::SgxsRead + 'a> Iterator for Pages<'a, R> {
    type Item = sgxs::Result<(u64, PageCharacteristic)>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_offset = self.last_offset.map_or(0, |l| l + 4096);
        self.last_offset = Some(cur_offset);
        if let Some((page_offset, _)) = self.last_read_page {
            if cur_offset < page_offset {
                Some(Ok((cur_offset, PageCharacteristic::Gap)))
            } else {
                match self.next_page() {
                    Err(e) => Some(Err(e)),
                    Ok(next) => Some(Ok(
                        std::mem::replace(&mut self.last_read_page, next).unwrap()
                    )),
                }
            }
        } else {
            // gaps until the end
            if self.size.is_none() {
                self.size = Some(size_fit_natural(cur_offset));
            };
            if cur_offset >= self.size.unwrap() {
                None
            } else {
                Some(Ok((cur_offset, PageCharacteristic::Gap)))
            }
        }
    }
}

impl<'a, R: sgxs::SgxsRead + 'a> Pages<'a, R> {
    fn next_page(&mut self) -> sgxs::Result<Option<(u64, PageCharacteristic)>> {
        Ok(self.reader.read_page()?.map(|(eadd, chunks, data)| {
            (
                eadd.offset,
                PageCharacteristic::Page {
                    flags: eadd.secinfo.flags,
                    measured_chunks: chunks,
                    data: classify_data(&data),
                },
            )
        }))
    }

    fn new(reader: &'a mut R) -> sgxs::Result<Self> {
        let (info, reader) = sgxs::PageReader::new(reader)?;
        let size = if info.sized {
            Some(info.ecreate.size)
        } else {
            None
        };
        let mut ret = Pages {
            reader: reader,
            last_offset: None,
            last_read_page: None,
            size,
        };
        ret.last_read_page = ret.next_page()?;
        Ok(ret)
    }
}

fn summary<P: AsRef<Path>>(path: P) -> sgxs::Result<()> {
    let mut file = File::open(path)?;
    let mut pages = Pages::new(&mut file)?;
    let w = if let Some(s) = pages.size {
        format!("{:x}", s - 1).len()
    } else {
        println!("(unsized)");
        8
    };
    let mut last = None;
    let mut last_offset = 0;
    loop {
        let mut cur_offset = None;
        let cur = if let Some(res) = pages.next() {
            let cur = res?;
            cur_offset = Some(cur.0);
            Some(cur)
        } else {
            None
        };
        if cur == last {
            break;
        }
        let collapse = match (&cur, &last) {
            (&Some((_, ref cur_c)), &Some((_, ref last_c))) if cur_c != last_c => true,
            (&None, &Some(_)) => true,
            _ => false,
        };
        if collapse {
            let last = std::mem::replace(&mut last, cur).unwrap();
            println!(
                "{:w$x}-{:w$x} {}",
                last.0,
                last_offset + 0xfff,
                last.1,
                w = w
            );
        } else if last == None {
            last = cur;
        }
        cur_offset.map(|cur_offset| last_offset = cur_offset);
    }
    Ok(())
}

fn dump_mem<P: AsRef<Path>>(path: P) -> sgxs::Result<()> {
    use std::io::{copy, repeat, stdout, Read, Write};

    let mut file = File::open(path)?;
    let (_, mut reader) = sgxs::PageReader::new(&mut file)?;
    let mut last_offset = None;
    loop {
        if let Some((eadd, _, data)) = reader.read_page()? {
            copy(
                &mut repeat(0).take(eadd.offset - last_offset.map_or(0, |lo| lo + 4096)),
                &mut stdout(),
            )
            .unwrap();
            stdout().write(&data).unwrap();
            last_offset = Some(eadd.offset);
        } else {
            break;
        }
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args_os();
    let name = args.next();
    let command = args.next();
    let file = args.next();
    if let (Some(command), Some(file)) = (command, file) {
        if &command[..] == OsStr::new("list-all") {
            list_all(file).unwrap();
            return;
        } else if &command[..] == OsStr::new("list-pages") {
            list_pages(file).unwrap();
            return;
        } else if &command[..] == OsStr::new("info") {
            summary(file).unwrap();
            return;
        } else if &command[..] == OsStr::new("dump-mem") {
            dump_mem(file).unwrap();
            return;
        }
    }
    let s1;
    let s2;
    let s3;
    println!(
        "Usage: {} <mode> <file>",
        if let Some(s) = name {
            s1 = s;
            s2 = Path::new(&s1).display();
            &s2 as &fmt::Display
        } else {
            s3 = "sgxs-info";
            &s3 as &_
        }
    );
}
