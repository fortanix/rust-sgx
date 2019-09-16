/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::mem;

use byteorder::{ByteOrder, LE};
use num_traits::FromPrimitive;
use openssl::x509::X509;
use percent_encoding::percent_decode;

// ====================================================
// ================= TYPE DEFINITIONS =================
// ====================================================

pub struct Quote<'a> {
    header: QuoteHeader<'a>,
    report_body: Cow<'a, [u8]>,
    signature: Cow<'a, [u8]>,
}

pub enum QuoteHeader<'a> {
    V3 {
        attestation_key_type: Quote3AttestationKeyType,
        qe3_svn: u16,
        pce_svn: u16,
        qe3_vendor_id: Cow<'a, [u8]>,
        user_data: Cow<'a, [u8]>,
    },
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum Quote3AttestationKeyType {
    EcdsaP256 = 2,
    EcdsaP384 = 3,
}

pub const QE3_VENDOR_ID_INTEL: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

pub type QeId<'a> = Cow<'a, [u8]>;

pub struct Quote3SignatureEcdsaP256<'a> {
    signature: Cow<'a, [u8]>,
    attestation_public_key: Cow<'a, [u8]>,
    qe3_report: Cow<'a, [u8]>,
    qe3_signature: Cow<'a, [u8]>,
    authentication_data: Cow<'a, [u8]>,
    certification_data_type: CertificationDataType,
    certification_data: Cow<'a, [u8]>,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, ToPrimitive)]
pub enum CertificationDataType {
    PpidCleartext = 1,
    PpidEncryptedRsa2048 = 2,
    PpidEncryptedRsa3072 = 3,
    PckCertificate = 4,
    PckCertificateChain = 5,
    EcdsaSignatureAuxiliaryData = 6,
    PlatformManifest = 7,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Qe3CertDataPpid<'a> {
    pub ppid: Cow<'a, [u8]>,
    pub cpusvn: Cow<'a, [u8]>,
    pub pcesvn: u16,
    pub pceid: u16,
}

#[derive(Clone)]
pub struct Qe3CertDataPckCertChain {
    pub leaf_cert: X509,
    pub intermed_cert: X509,
    pub root_cert: X509,
}

pub type Result<T> = ::std::result::Result<T, ::failure::Error>;

// ===========================================
// ================= PARSING =================
// ===========================================

trait TakePrefix: Sized {
    fn take_prefix(&mut self, mid: usize) -> Result<Self>;
}

impl<'a, T: 'a> TakePrefix for &'a [T] {
    fn take_prefix(&mut self, mid: usize) -> Result<Self> {
        if let (Some(prefix), Some(rest)) = (self.get(..mid), self.get(mid..)) {
            *self = rest;
            Ok(prefix)
        } else {
            bail!("Unexpected end of quote")
        }
    }
}

pub trait Quote3Signature<'a>: Sized {
    fn parse(type_: Quote3AttestationKeyType, data: &'a [u8]) -> Result<Self>;
}

pub trait Qe3CertData<'a>: Sized {
    fn parse(type_: CertificationDataType, data: &'a [u8]) -> Result<Self>;
}

const QUOTE_HEADER_LEN: usize = 48;
const QUOTE_SIGNATURE_START_BYTE: usize = 436;
const ISV_ENCLAVE_REPORT_SIG_LEN: usize = 64;
const ATT_KEY_PUB_LEN: usize = 64;
const REPORT_DATA_OFFSET: usize = 320;
const PCK_HASH_LEN: usize = 32;
const ECDSA_P256_SIGNATURE_LEN: usize = 64;
const ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
const QE3_VENDOR_ID_LEN: usize = 16;
const QE3_USER_DATA_LEN: usize = 20;
const REPORT_BODY_LEN: usize = 384;
const CPUSVN_LEN: usize = 16;
const QUOTE_VERSION_3: u16 = 3;

impl<'a> Quote<'a> {
    // This vector of the Quote Header and ISV Enclave Report is the material signed
    // by the Quoting Enclave's Attestation Key and should be returned in raw form to
    // verify the Attestation Key's signature. Specifically, the header's version
    // number should also be kept intact in the vector, rather than being abstracted
    // into the Header enum.
    pub fn raw_header_and_body(quote: &'a [u8]) -> Result<Vec<u8>> {
        Ok(quote[0..(QUOTE_HEADER_LEN + REPORT_BODY_LEN)].to_vec())
    }

    // The Report Data of the QE Report holds a SHA256 hash of (ECDSA Attestation Key || QE
    // Authentication data) || 32-0x00's. This hash must be verified for attestation.
    // The Report comes after the ISV Enclave Report Signature and Attestation Public Key in the
    // Quote Signature. The structure of the QE Report in the Quote Signature is identical
    // to the structure of any enclave's Report, so the Report Data begins at byte 320 of the Report.
    pub fn raw_pck_hash(quote: &'a [u8]) -> Result<&[u8]> {
        let start_byte = QUOTE_SIGNATURE_START_BYTE
            + ISV_ENCLAVE_REPORT_SIG_LEN
            + ATT_KEY_PUB_LEN
            + REPORT_DATA_OFFSET;
        Ok(&quote[start_byte.. start_byte + PCK_HASH_LEN])
    }

    pub fn parse(mut quote: &'a [u8]) -> Result<Quote<'a>> {
        let version = quote.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        if version != QUOTE_VERSION_3 {
            bail!("Unknown quote version: {}", version);
        }
        let att_key_type = quote.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let attestation_key_type = Quote3AttestationKeyType::from_u16(att_key_type)
            .ok_or_else(|| format_err!("Unknown attestation key type: {}", att_key_type))?;
        let reserved = quote.take_prefix(mem::size_of::<u32>()).map(LE::read_u32)?;
        if reserved != 0 {
            bail!("Data in reserved field: {:08x}", reserved);
        }
        let qe3_svn = quote.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let pce_svn = quote.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let qe3_vendor_id = quote.take_prefix(QE3_VENDOR_ID_LEN)?.into();
        let user_data = quote.take_prefix(QE3_USER_DATA_LEN)?.into();
        let report_body = quote.take_prefix(REPORT_BODY_LEN)?.into();

        Ok(Quote {
            header: QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                qe3_vendor_id,
                user_data,
            },
            report_body,
            signature: quote.into(),
        })
    }
}

impl<'a> Quote3Signature<'a> for Quote3SignatureEcdsaP256<'a> {
    fn parse(type_: Quote3AttestationKeyType, mut data: &'a [u8]) -> Result<Self> {
        if type_ != Quote3AttestationKeyType::EcdsaP256 {
            bail!("Invalid attestation key type: {:?}", type_)
        }

        let sig_len = data.take_prefix(mem::size_of::<u32>()).map(LE::read_u32)?;
        if sig_len as usize != data.len() {
            bail!(
                "Invalid signature length. Got {}, expected {}",
                data.len(),
                sig_len
            );
        }
        let signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?.into();
        let attestation_public_key = data.take_prefix(ECDSA_P256_PUBLIC_KEY_LEN)?.into();
        let qe3_report = data.take_prefix(REPORT_BODY_LEN)?.into();
        let qe3_signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?.into();
        let authdata_len = data.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let authentication_data = data.take_prefix(authdata_len as _)?.into();
        let cd_type = data.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let certification_data_type = CertificationDataType::from_u16(cd_type)
            .ok_or_else(|| format_err!("Unknown certification data type: {}", cd_type))?;
        let certdata_len = data.take_prefix(mem::size_of::<u32>()).map(LE::read_u32)?;
        if certdata_len as usize != data.len() {
            bail!(
                "Invalid certification data length. Got {}, expected {}",
                data.len(),
                certdata_len
            );
        }

        Ok(Quote3SignatureEcdsaP256 {
            signature,
            attestation_public_key,
            qe3_report,
            qe3_signature,
            authentication_data,
            certification_data_type,
            certification_data: data.into(),
        })
    }
}

impl<'a> Qe3CertData<'a> for Qe3CertDataPpid<'a> {
    fn parse(type_: CertificationDataType, mut data: &'a [u8]) -> Result<Self> {
        let ppid_len = match type_ {
            CertificationDataType::PpidCleartext => bail!(
                "PPID clear text not implemented. Data length = {}",
                data.len()
            ),
            CertificationDataType::PpidEncryptedRsa2048 => 256,
            CertificationDataType::PpidEncryptedRsa3072 => 384,
            _ => bail!("Invalid certification data type: {:?}", type_),
        };

        let ppid = data.take_prefix(ppid_len)?.into();
        let cpusvn = data.take_prefix(CPUSVN_LEN)?.into();
        let pcesvn = data.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        let pceid = data.take_prefix(mem::size_of::<u16>()).map(LE::read_u16)?;
        if !data.is_empty() {
            bail!(
                "Invalid certification data length for type {:?}: {}",
                type_,
                data.len()
            );
        }

        Ok(Qe3CertDataPpid {
            ppid,
            cpusvn,
            pcesvn,
            pceid,
        })
    }
}

impl Qe3CertData<'_> for Qe3CertDataPckCertChain {
    fn parse(type_: CertificationDataType, data: &[u8]) -> Result<Self> {
        if type_ != CertificationDataType::PckCertificateChain {
            bail!("Invalid certification data type: {:?}", type_);
        }

        let utf8_decoded = percent_decode(data).decode_utf8()?.into_owned();
        let pck_cert_chain = X509::stack_from_pem(&utf8_decoded.as_bytes()[..])?;
        let leaf_cert = pck_cert_chain[0].clone();
        let intermed_cert = pck_cert_chain[1].clone();
        let root_cert = pck_cert_chain[2].clone();

        Ok(Qe3CertDataPckCertChain {
            leaf_cert,
            intermed_cert,
            root_cert,
        })
    }
}

// =============================================
// ================= ACCESSORS =================
// =============================================

impl<'a> Quote<'a> {
    pub fn header(&self) -> &QuoteHeader<'a> {
        &self.header
    }

    pub fn report_body(&self) -> &[u8] {
        &self.report_body
    }

    pub fn signature<'b, T: Quote3Signature<'b>>(&'b self) -> Result<T> {
        let QuoteHeader::V3 {
            attestation_key_type,
            ..
        } = self.header;
        T::parse(attestation_key_type, &self.signature)
    }

    pub fn clone_owned(&self) -> Quote<'static> {
        Quote {
            header: self.header.clone_owned(),
            report_body: (*self.report_body).to_owned().into(),
            signature: (*self.signature).to_owned().into(),
        }
    }
}

impl<'a> QuoteHeader<'a> {
    pub fn clone_owned(&self) -> QuoteHeader<'static> {
        match *self {
            QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                ref qe3_vendor_id,
                ref user_data,
            } => QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                qe3_vendor_id: (**qe3_vendor_id).to_owned().into(),
                user_data: (**user_data).to_owned().into(),
            },
        }
    }
}

impl<'a> Quote3SignatureEcdsaP256<'a> {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn attestation_public_key(&self) -> &[u8] {
        &self.attestation_public_key
    }

    pub fn qe3_report(&self) -> &[u8] {
        &self.qe3_report
    }

    pub fn qe3_signature(&self) -> &[u8] {
        &self.qe3_signature
    }

    pub fn authentication_data(&self) -> &[u8] {
        &self.authentication_data
    }

    pub fn certification_data_type(&self) -> CertificationDataType {
        self.certification_data_type
    }

    pub fn certification_data<'b, T: Qe3CertData<'b>>(&'b self) -> Result<T> {
        T::parse(self.certification_data_type, &self.certification_data)
    }

    pub fn clone_owned(&self) -> Quote3SignatureEcdsaP256<'static> {
        Quote3SignatureEcdsaP256 {
            signature: (*self.signature).to_owned().into(),
            attestation_public_key: (*self.attestation_public_key).to_owned().into(),
            qe3_report: (*self.qe3_report).to_owned().into(),
            qe3_signature: (*self.qe3_signature).to_owned().into(),
            authentication_data: (*self.authentication_data).to_owned().into(),
            certification_data_type: self.certification_data_type,
            certification_data: (*self.certification_data).to_owned().into(),
        }
    }
}

impl<'a> Qe3CertDataPpid<'a> {
    pub fn clone_owned(&self) -> Qe3CertDataPpid<'static> {
        Qe3CertDataPpid {
            ppid: (*self.ppid).to_owned().into(),
            cpusvn: (*self.cpusvn).to_owned().into(),
            pcesvn: self.pcesvn,
            pceid: self.pceid,
        }
    }
}

impl Qe3CertDataPckCertChain {
    pub fn clone_owned(&self) -> Qe3CertDataPckCertChain {
        Qe3CertDataPckCertChain {
            leaf_cert: (*self.leaf_cert).to_owned().into(),
            intermed_cert: (*self.intermed_cert).to_owned().into(),
            root_cert: (*self.root_cert).to_owned().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_certdata_ppid() {
        const TEST_QUOTE: &[u8] = &*include_bytes!("../tests/quote_raw_tcb.bin");
        const QE_ID: [u8; 16] = [
            0x00, 0xfb, 0xe6, 0x73, 0x33, 0x36, 0xea, 0xf7, 0xa4, 0xe3, 0xd8, 0xb9, 0x66, 0xa8,
            0x2e, 0x64,
        ];

        const EXPECTED_PPID: &[u8; 384] = include_bytes!("../tests/encrypted_ppid.bin");
        const EXPECTED_CPUSVN: [u8; 16] = [
            0x05, 0x05, 0x02, 0x05, 0xff, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        const EXPECTED_PCESVN: u16 = 6;
        const EXPECTED_PCEID: u16 = 0;

        let quote = Quote::parse(TEST_QUOTE).unwrap();
        let &QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ref user_data,
            ..
        } = quote.header();

        assert_eq!(qe3_vendor_id, &&QE3_VENDOR_ID_INTEL[..]);
        let mut ud = QE_ID.to_vec();
        ud.resize(20usize, 0u8);
        assert_eq!(user_data, &ud);

        assert_eq!(attestation_key_type, Quote3AttestationKeyType::EcdsaP256);
        let sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();

        assert_eq!(
            sig.certification_data_type(),
            CertificationDataType::PpidEncryptedRsa3072
        );
        let cd = sig.certification_data::<Qe3CertDataPpid>().unwrap();

        assert_eq!(cd.ppid, &EXPECTED_PPID[..]);
        assert_eq!(cd.cpusvn, &EXPECTED_CPUSVN[..]);
        assert_eq!(cd.pcesvn, EXPECTED_PCESVN);
        assert_eq!(cd.pceid, EXPECTED_PCEID);
    }
}
