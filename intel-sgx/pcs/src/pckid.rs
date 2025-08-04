/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::convert::TryInto;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Error, ErrorKind};
use std::path::Path;

use rustc_serialize::hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};

use crate::{CpuSvn, EncPpid, PceId, PceIsvsvn, QeId};

#[derive(Clone, Serialize, Deserialize, Debug, Default, Hash, PartialEq, Eq)]
pub struct PckID {
    pub enc_ppid: EncPpid,
    pub pce_id: PceId,
    pub cpu_svn: CpuSvn,
    pub pce_isvsvn: PceIsvsvn,
    pub qe_id: QeId,
}

impl ToString for PckID {
    fn to_string(&self) -> String {
        let enc_ppid = self.enc_ppid.as_slice();
        let mut string = String::from("==[ PckId ]==\n");
        string += format!(" Info:\n").as_str();
        string += format!(
            "   Encr. PPID:  {}..{}\n",
            enc_ppid[..12].to_hex(),
            enc_ppid[enc_ppid.len() - 3..].to_hex()
        )
        .as_str();
        string += format!("   pce_id:      {}\n", self.pce_id.to_le_bytes().to_hex()).as_str();
        string += format!("   cpu svn:     {}\n", self.cpu_svn.as_slice().to_hex()).as_str();
        string += format!("   pce isvsvn:  {}\n", self.pce_isvsvn.to_le_bytes().to_hex()).as_str();
        string += format!("   qe_id:       {}\n", self.qe_id.as_slice().to_hex()).as_str();
        return string;
    }
}

fn parse_hex_array<'a>(chunk: &'a str, expected_bytes: usize) -> io::Result<Vec<u8>> {
    if chunk.len() != expected_bytes * 2 {
        return Err(Error::new(ErrorKind::InvalidData, "Parse error, incorrect field length"));
    }

    chunk
        .from_hex()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cannot parse as hexadecimal"))
}

/// Iterator adapter that returns Results instead of Options.
struct ResultAdapter<I: Iterator, E, F: Fn() -> E>(I, F);

impl<I: Iterator, E, F: Fn() -> E> ResultAdapter<I, E, F> {
    fn next(&mut self) -> std::result::Result<I::Item, E> {
        self.0.next().ok_or_else(|| self.1())
    }
}

impl PckID {
    pub fn parse_line(line: &str) -> io::Result<Self> {
        let mut fields = ResultAdapter(line.split(","), || Error::new(ErrorKind::InvalidData, "Too few fields"));

        let enc_ppid: EncPpid = parse_hex_array(fields.next()?, 384)?;
        let pce_id: PceId = u16::from_str_radix(fields.next()?, 16)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Cannot parse as hexadecimal"))?;
        let cpu_svn: CpuSvn = parse_hex_array(fields.next()?, 16)?
            .try_into()
            .map_err(|_e| Error::new(ErrorKind::InvalidData, "Incorrect length cpu_svn"))?;
        let pce_isvsvn: PceIsvsvn = u16::from_str_radix(fields.next()?, 16)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Cannot parse as hexadecimal"))?;
        let qe_id: QeId = parse_hex_array(fields.next()?, 16)?
            .try_into()
            .map_err(|_e| Error::new(ErrorKind::InvalidData, "Incorrect length qe_id"))?;

        Ok(PckID {
            enc_ppid,
            pce_id,
            cpu_svn,
            pce_isvsvn,
            qe_id,
        })
    }

    pub fn parse_file(file: &Path) -> io::Result<Vec<Self>> {
        let file = File::open(file)?;
        let mut pck_ids = Vec::new();

        for line_res in BufReader::new(file).lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let pck_id = PckID::parse_line(trimmed)?;
            pck_ids.push(pck_id);
        }

        Ok(pck_ids)
    }
}
