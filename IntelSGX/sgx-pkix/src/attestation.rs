/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::io::Cursor;
use std::borrow::Cow;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use pkix::yasna::tags::{TAG_BITSTRING, TAG_UTF8STRING};
use pkix::yasna::{ASN1Result, BERReader, DERWriter, BERDecodable};
use pkix::types::*;
use pkix::DerWrite;
use sgx_isa::{Attributes, AttributesFlags, Miscselect, Report};

use super::oid;
use super::{Error, Result};

pub fn miscselect_to_bytes(miscselect: &Miscselect) -> Vec<u8> {
    let mut buf = vec![0; 4];
    let _ = Cursor::new(&mut buf[..]).write_u32::<LittleEndian>(miscselect.bits());
    buf
}

pub fn miscselect_from_bytes(bytes: &[u8]) -> Result<Miscselect> {
    if bytes.len() != 4 {
        return Err(Error::InvalidLength);
    }
    Ok(Cursor::new(bytes).read_u32::<LittleEndian>().ok().and_then(Miscselect::from_bits).ok_or(Error::InvalidMiscselect)?)
}

pub fn attributes_to_bytes(attributes: &Attributes) -> Vec<u8> {
    let mut buf = vec![0; 16];
    {
        let mut cursor = Cursor::new(&mut buf[..]);
        cursor.write_u64::<LittleEndian>(attributes.flags.bits()).unwrap();
        cursor.write_u64::<LittleEndian>(attributes.xfrm).unwrap();
    }
    buf
}

pub fn attributes_from_bytes(bytes: &[u8]) -> Result<Attributes> {
    if bytes.len() != 16 {
        return Err(Error::InvalidLength);
    }

    let mut cursor = Cursor::new(bytes);
    let flags = cursor.read_u64::<LittleEndian>().ok()
        .and_then(AttributesFlags::from_bits).ok_or(Error::InvalidAttributes)?;
    let xfrm = cursor.read_u64::<LittleEndian>().map_err(|_|Error::InvalidAttributes)?;

    Ok(Attributes {
        flags: flags,
        xfrm: xfrm,
    })
}

fn u16_to_bytes(val: u16) -> Vec<u8> {
    let mut buf = vec![0; 2];
    let _ = Cursor::new(&mut buf[..]).write_u16::<LittleEndian>(val);
    buf
}

pub fn isvprodid_to_bytes(isvprodid: u16) -> Vec<u8> {
    u16_to_bytes(isvprodid)
}

pub fn isvprodid_from_bytes(bytes: &[u8]) -> Result<u16> {
    if bytes.len() != 2 {
        return Err(Error::InvalidLength);
    }

    Ok(Cursor::new(bytes).read_u16::<LittleEndian>().map_err(|_| Error::InvalidIsvprodid)?)
}

pub fn isvsvn_to_bytes(isvsvn: u16) -> Vec<u8> {
    u16_to_bytes(isvsvn)
}

pub fn isvsvn_from_bytes(bytes: &[u8]) -> Result<u16> {
    if bytes.len() != 2 {
        return Err(Error::InvalidLength);
    }

    Ok(Cursor::new(bytes).read_u16::<LittleEndian>().map_err(|_| Error::InvalidIsvsvn)?)
}

pub struct SgxName(Vec<(ObjectIdentifier, NameComponent)>);

impl SgxName {
    pub fn append(&mut self, mut vec: Vec<(ObjectIdentifier, NameComponent)>) {
        self.0.append(&mut vec);
    }
    
    pub fn from_report(report: &Report, include_reportdata: bool) -> Self {
        let mut name = vec![
            (oid::sgxCpusvn.clone(),report.cpusvn[..].to_owned().into()),
            (oid::sgxMiscselect.clone(),miscselect_to_bytes(&report.miscselect).into()),
            (oid::sgxAttributes.clone(),attributes_to_bytes(&report.attributes).into()),
            (oid::sgxMrenclave.clone(),report.mrenclave[..].to_owned().into()),
            (oid::sgxMrsigner.clone(),report.mrsigner[..].to_owned().into()),
            (oid::sgxIsvprodid.clone(),isvprodid_to_bytes(report.isvprodid).into()),
            (oid::sgxIsvsvn.clone(),isvsvn_to_bytes(report.isvsvn).into()),
        ];
        if include_reportdata {
            name.push((oid::sgxReportdata.clone(),report.reportdata[..].to_owned().into()));
        }
        SgxName(name)
    }

    pub fn to_name(&self) -> Name {
        let name = self.0.iter().map(|&(ref oid,ref v)| (oid.clone(), match &v {
            NameComponent::Str(ref s) => TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, s.as_bytes().to_owned()),
            NameComponent::Bytes(ref b) => {
                // mbedTLS does not support OCTET STRING in any name component. It does
                // support BITSTRING. Adjust binary to be ok for BIT STRING encoding.
                // First byte of bitstring is the number of unused bits.
                // We always have an even number of bytes.
                let mut bytes = Vec::with_capacity(1 + b.len());
                bytes.push(0);
                bytes.extend_from_slice(b);
                TaggedDerValue::from_tag_and_bytes(TAG_BITSTRING, bytes)
            },
        })).collect();
        Name { value: name }
    }
}

pub(crate) fn reconstruct_sgx_report(subject: &Name, attestation: &AttestationInlineSgxLocal) -> Result<Report> {
    fn bytes(src: &TaggedDerValue) -> Result<&[u8]> {
        src.as_bytes().ok_or(Error::InvalidValue)
    }

    fn assign_slice(dst: &mut [u8], src: &[u8]) -> Result<()> {
        if dst.len() != src.len() {
            return Err(Error::InvalidLength)
        }
        dst.copy_from_slice(src);
        Ok(())
    }

    let cpusvn     = subject.get(&oid::sgxCpusvn).ok_or(Error::MissingCpusvn)?;
    let miscselect = subject.get(&oid::sgxMiscselect).ok_or(Error::MissingMiscselect)?;
    let attributes = subject.get(&oid::sgxAttributes).ok_or(Error::MissingAttributes)?;
    let mrenclave  = subject.get(&oid::sgxMrenclave).ok_or(Error::MissingMrenclave)?;
    let mrsigner   = subject.get(&oid::sgxMrsigner).ok_or(Error::MissingMrsigner)?;
    let isvprodid  = subject.get(&oid::sgxIsvprodid).ok_or(Error::MissingIsvprodid)?;
    let isvsvn     = subject.get(&oid::sgxIsvsvn).ok_or(Error::MissingIsvsvn)?;
    let reportdata = subject.get(&oid::sgxReportdata).ok_or(Error::MissingReportdata)?;

    let mut report = Report::default();
    bytes(cpusvn).and_then(|b| assign_slice(&mut report.cpusvn, b)).map_err(|_| Error::InvalidCpusvn)?;
    bytes(mrenclave).and_then(|b| assign_slice(&mut report.mrenclave, b)).map_err(|_| Error::InvalidMrenclave)?;
    bytes(mrsigner).and_then(|b| assign_slice(&mut report.mrsigner, b)).map_err(|_| Error::InvalidMrsigner)?;
    bytes(reportdata).and_then(|b| assign_slice(&mut report.reportdata, b)).map_err(|_| Error::InvalidReportdata)?;

    report.miscselect = bytes(miscselect).and_then(|b| miscselect_from_bytes(b)).map_err(|_| Error::InvalidMiscselect)?;
    report.attributes = bytes(attributes).and_then(|b| attributes_from_bytes(b)).map_err(|_| Error::InvalidAttributes)?;

    report.isvprodid = bytes(isvprodid).and_then(|b| isvprodid_from_bytes(b))?;
    report.isvsvn = bytes(isvsvn).and_then(|b| isvsvn_from_bytes(b))?;

    assign_slice(&mut report.keyid, &attestation.keyid).map_err(|_| Error::InvalidKeyid)?;
    assign_slice(&mut report.mac, &attestation.mac).map_err(|_| Error::InvalidMac)?;

    Ok(report)
}

// IntelLocal ::= SEQUENCE {
//     KEYID   OCTET STRING
//     MAC     OCTET STRING
// }

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttestationInlineSgxLocal<'a, 'b> {
    pub keyid: Cow<'a, [u8]>,
    pub mac: Cow<'b, [u8]>,
}

impl<'a, 'b> HasOid for AttestationInlineSgxLocal<'a, 'b> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::attestationInlineSgxLocal
    }
}

impl<'a, 'b> DerWrite for AttestationInlineSgxLocal<'a, 'b> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_bytes(&self.keyid);
            w.next().write_bytes(&self.mac);
        })
    }
}

impl BERDecodable for AttestationInlineSgxLocal<'static, 'static> {
    fn decode_ber<'p, 'q>(reader: BERReader<'p, 'q>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let keyid = r.next().read_bytes()?;
            let mac = r.next().read_bytes()?;
            Ok(AttestationInlineSgxLocal {
                keyid: Cow::Owned(keyid),
                mac: Cow::Owned(mac),
            })
        })
    }
}

// IntelQuote ::= SEQUENCE {
//     qe     Name
//     quote  OCTET STRING
// }

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct AttestationEmbeddedIntelQuote<'a> {
    pub qe: Name,
    pub quote: Cow<'a, [u8]>,
}

impl<'a> HasOid for AttestationEmbeddedIntelQuote<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::attestationEmbeddedIntelQuote
    }
}

impl<'a> AttestationEmbeddedIntelQuote<'a> {
    pub fn quote(&self) -> &[u8] {
        &self.quote
    }
}

impl<'a> DerWrite for AttestationEmbeddedIntelQuote<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            self.qe.write(w.next());
            w.next().write_bytes(&self.quote);
        })
    }
}

impl BERDecodable for AttestationEmbeddedIntelQuote<'static> {
    fn decode_ber<'p, 'q>(reader: BERReader<'p, 'q>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let qe = Name::decode_ber(r.next())?;
            let quote = r.next().read_bytes()?;
            Ok(AttestationEmbeddedIntelQuote{
                qe: qe,
                quote: Cow::Owned(quote)
            })
        })
    }
}

// IntelIasReportv2 ::= SEQUENCE {
//     httpBody      OCTET STRING
//     iasreportSig  OCTET STRING
//     certificates  SEQUENCE OF Certificate
// }

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttestationEmbeddedIasReport<'a, 'b, 'c> {
    pub http_body: Cow<'a, [u8]>,
    pub report_sig: Cow<'b, [u8]>,
    pub certificates: Vec<DerSequence<'c>>,
}

impl<'a, 'b, 'c> HasOid for AttestationEmbeddedIasReport<'a, 'b, 'c> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::attestationEmbeddedIasReport
    }
}

impl<'a, 'b, 'c> DerWrite for AttestationEmbeddedIasReport<'a, 'b, 'c> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_bytes(&self.http_body);
            w.next().write_bytes(&self.report_sig);
            w.next().write_sequence(|w| for cert in &self.certificates {
                cert.write(w.next())
            });
        })
    }
}

impl BERDecodable for AttestationEmbeddedIasReport<'static, 'static, 'static> {
    fn decode_ber<'p, 'q>(reader: BERReader<'p, 'q>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let http_body = r.next().read_bytes()?;
            let report_sig = r.next().read_bytes()?;
            let certificates = r.next().read_sequence(|r| {
                let mut certificates = Vec::<DerSequence<'static>>::new();

                loop {
                    match r.read_optional(|r| DerSequence::decode_ber(r)) {
                        Ok(Some(cert)) => certificates.push(cert),
                        Ok(None) => break,
                        Err(e) => return Err(e),
                    }
                }

                Ok(certificates)
            })?;
            Ok(AttestationEmbeddedIasReport {
                http_body: Cow::Owned(http_body),
                report_sig: Cow::Owned(report_sig),
                certificates,
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttestationEmbeddedFqpe<'a, 'b> {
    pub app_cert: Cow<'a, [u8]>,
    pub node_cert: Cow<'b, [u8]>,
}

impl<'a, 'b> HasOid for AttestationEmbeddedFqpe<'a, 'b> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::attestationEmbeddedFqpe
    }
}

impl<'a, 'b> DerWrite for AttestationEmbeddedFqpe<'a, 'b> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_bytes(&self.app_cert);
            w.next().write_bytes(&self.node_cert);
        })
    }
}

impl BERDecodable for AttestationEmbeddedFqpe<'static, 'static> {
    fn decode_ber<'p, 'q>(reader: BERReader<'p, 'q>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let app_cert = r.next().read_bytes()?;
            let node_cert = r.next().read_bytes()?;
            Ok(AttestationEmbeddedFqpe {
                app_cert: Cow::Owned(app_cert),
                node_cert: Cow::Owned(node_cert),
            })
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuoteResult {
    /// For Intel attestatations, the EPID signature from Intel QE.
    /// For Fortanix attestations, DER encoding of the "EnclaveCertificate" from FQPE.
    quote: Vec<u8>,

    /// SGX report (EREPORT) from the Intel or Fortanix quoting enclave for the quote.
    qe_report: Vec<u8>,
}

impl QuoteResult {
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(quote: T, qe_report: U) -> Self {
        QuoteResult {
            quote: quote.into(),
            qe_report: qe_report.into(),
        }
    }

    pub fn quote(&self) -> &[u8] {
        &self.quote
    }

    pub fn qe_report(&self) -> &[u8] {
        &self.qe_report
    }
}
