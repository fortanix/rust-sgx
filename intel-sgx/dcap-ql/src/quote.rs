/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


use byteorder::{ByteOrder, LE};
#[cfg(feature = "verify")]
use mbedtls::ecp::{EcGroup, EcPoint};
#[cfg(feature = "verify")]
use mbedtls::pk::{Pk, EcGroupId};
#[cfg(feature = "verify")]
use mbedtls::hash::{self, Md};
use num_traits::FromPrimitive;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "verify")]
use sgx_isa::Report;
use std::borrow::Cow;
use std::mem;
use anyhow::bail;

// ====================================================
// ================= TYPE DEFINITIONS =================
// ====================================================

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Quote<'a> {
    header: QuoteHeader<'a>,
    report_body: Cow<'a, [u8]>,
    signature: Cow<'a, [u8]>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Quote3AttestationKeyType {
    EcdsaP256 = 2,
    EcdsaP384 = 3,
}

pub const QE3_VENDOR_ID_INTEL: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

pub type QeId<'a> = Cow<'a, [u8]>;

#[derive(Debug)]
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Qe3CertDataPckCertChain<'a> {
    pub certs: Vec<Cow<'a, str>>,
}

pub type RawQe3CertData<'a> = Cow<'a, [u8]>;

pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

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

impl<'a, T: 'a + Clone> TakePrefix for Cow<'a, [T]> {
    fn take_prefix(&mut self, mid: usize) -> Result<Self> {
        if mid <= self.len() {
            match self {
                &mut Cow::Borrowed(ref mut slice) => slice.take_prefix(mid).map(Cow::Borrowed),
                &mut Cow::Owned(ref mut vec) => {
                    let rest = vec.split_off(mid);
                    Ok(Cow::Owned(mem::replace(vec, rest)))
                },
            }
        } else {
            bail!("Unexpected end of quote")
        }
    }
}

impl<'a> TakePrefix for &'a str {
    fn take_prefix(&mut self, mid: usize) -> Result<Self> {
        if let (Some(prefix), Some(rest)) = (self.get(..mid), self.get(mid..)) {
            *self = rest;
            Ok(prefix)
        } else {
            bail!("Unexpected end of quote")
        }
    }
}

impl<'a> TakePrefix for Cow<'a, str> {
    fn take_prefix(&mut self, mid: usize) -> Result<Self> {
        if mid <= self.len() {
            match self {
                &mut Cow::Borrowed(ref mut slice) => slice.take_prefix(mid).map(Cow::Borrowed),
                &mut Cow::Owned(ref mut vec) => {
                    let rest = vec.split_off(mid);
                    Ok(Cow::Owned(mem::replace(vec, rest)))
                },
            }
        } else {
            bail!("Unexpected end of quote")
        }
    }
}

pub trait Quote3Signature<'a>: Sized {
    fn parse(type_: Quote3AttestationKeyType, data: Cow<'a, [u8]>) -> Result<Self>;
}

pub trait Qe3CertData<'a>: Sized {
    fn parse(type_: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self>;
}

const ECDSA_P256_SIGNATURE_LEN: usize = 64;
const ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
const QE3_VENDOR_ID_LEN: usize = 16;
const QE3_USER_DATA_LEN: usize = 20;
const REPORT_BODY_LEN: usize = 384;
const CPUSVN_LEN: usize = 16;
const QUOTE_VERSION_3: u16 = 3;

impl<'a> Quote<'a> {
    pub fn parse<T: Into<Cow<'a, [u8]>>>(quote: T) -> Result<Quote<'a>> {
        let mut quote = quote.into();

        let version = quote.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        if version != QUOTE_VERSION_3 {
            bail!("Unknown quote version: {}", version);
        }
        let att_key_type = quote.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let attestation_key_type = Quote3AttestationKeyType::from_u16(att_key_type)
            .ok_or_else(|| format_err!("Unknown attestation key type: {}", att_key_type))?;
        let reserved = quote.take_prefix(mem::size_of::<u32>()).map(|v| LE::read_u32(&v))?;
        if reserved != 0 {
            bail!("Data in reserved field: {:08x}", reserved);
        }
        let qe3_svn = quote.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let pce_svn = quote.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let qe3_vendor_id = quote.take_prefix(QE3_VENDOR_ID_LEN)?;
        let user_data = quote.take_prefix(QE3_USER_DATA_LEN)?;
        let report_body = quote.take_prefix(REPORT_BODY_LEN)?;

        Ok(Quote {
            header: QuoteHeader::V3 {
                attestation_key_type,
                qe3_svn,
                pce_svn,
                qe3_vendor_id,
                user_data,
            },
            report_body,
            signature: quote,
        })
    }
}

/// Convert IEEE P1363 ECDSA signature to RFC5480 ASN.1 representation.
#[cfg(feature = "verify")]
fn get_ecdsa_sig_der(sig: &[u8]) -> Result<Vec<u8>> {
    if sig.len() % 2 != 0 {
        bail!("sig not even: {}", sig.len());
    }

    let (r_bytes, s_bytes) = sig.split_at(sig.len() / 2);
    let r = num::BigUint::from_bytes_be(r_bytes);
    let s = num::BigUint::from_bytes_be(s_bytes);

    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_biguint(&r);
            writer.next().write_biguint(&s);
        })
    });

    Ok(der)
}

impl<'a> Quote3Signature<'a> for Quote3SignatureEcdsaP256<'a> {
    fn parse(type_: Quote3AttestationKeyType, mut data: Cow<'a, [u8]>) -> Result<Self> {
        if type_ != Quote3AttestationKeyType::EcdsaP256 {
            bail!("Invalid attestation key type: {:?}", type_)
        }

        let sig_len = data.take_prefix(mem::size_of::<u32>()).map(|v| LE::read_u32(&v))?;
        if sig_len as usize != data.len() {
            bail!(
                "Invalid signature length. Got {}, expected {}",
                data.len(),
                sig_len
            );
        }
        let signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
        let attestation_public_key = data.take_prefix(ECDSA_P256_PUBLIC_KEY_LEN)?;
        let qe3_report = data.take_prefix(REPORT_BODY_LEN)?;
        let qe3_signature = data.take_prefix(ECDSA_P256_SIGNATURE_LEN)?;
        let authdata_len = data.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let authentication_data = data.take_prefix(authdata_len as _)?;
        let cd_type = data.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let certification_data_type = CertificationDataType::from_u16(cd_type)
            .ok_or_else(|| format_err!("Unknown certification data type: {}", cd_type))?;
        let certdata_len = data.take_prefix(mem::size_of::<u32>()).map(|v| LE::read_u32(&v))?;
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
            certification_data: data,
        })
    }
}

impl<'a> Qe3CertData<'a> for Qe3CertDataPpid<'a> {
    fn parse(type_: CertificationDataType, mut data: Cow<'a, [u8]>) -> Result<Self> {
        let ppid_len = match type_ {
            CertificationDataType::PpidCleartext => bail!(
                "PPID clear text not implemented. Data length = {}",
                data.len()
            ),
            CertificationDataType::PpidEncryptedRsa2048 => 256,
            CertificationDataType::PpidEncryptedRsa3072 => 384,
            _ => bail!("Invalid certification data type: {:?}", type_),
        };

        let ppid = data.take_prefix(ppid_len)?;
        let cpusvn = data.take_prefix(CPUSVN_LEN)?;
        let pcesvn = data.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
        let pceid = data.take_prefix(mem::size_of::<u16>()).map(|v| LE::read_u16(&v))?;
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

impl<'a> Qe3CertData<'a> for RawQe3CertData<'a>{
    fn parse(_type_: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self> {
        Ok(data)
    }
}

impl<'a> Qe3CertData<'a> for Qe3CertDataPckCertChain<'a> {
    fn parse(type_: CertificationDataType, data: Cow<'a, [u8]>) -> Result<Self>{
        if type_ != CertificationDataType::PckCertificateChain {
            bail!("Invalid certification data type: {:?}", type_);
        }

        let mut data = match data {
             Cow::Borrowed(s) =>
                 std::str::from_utf8(s)
                     .map(Cow::Borrowed)
                     .map_err(|e| format_err!("Invalid certificate format: {}", e))?,
             Cow::Owned(s) =>
                 String::from_utf8(s)
                     .map(Cow::Owned)
                     .map_err(|e| format_err!("Invalid certificate format: {}", e))?,
        };
        // TODO: use pkix PemBlock parser
        let mut certs = vec![];
        let mark = "-----END CERTIFICATE-----";
        while let Some(pos) = data.find(mark) {
            certs.push(data.take_prefix(pos + mark.len()).expect("validated -- pos is always valid"));
            if let Some(start) = data.find("-") {
                data.take_prefix(start).unwrap(); //validated -- start is always valid
            }
        }
        Ok(Qe3CertDataPckCertChain{
            certs
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

    pub fn signature<T: Quote3Signature<'a>>(&self) -> Result<T> {
        let QuoteHeader::V3 {
            attestation_key_type,
            ..
        } = self.header;
        T::parse(attestation_key_type, self.signature.clone())
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

    #[cfg(feature = "verify")]
    fn attestation_pk(&self) -> Result<Pk> {
        let mut pt = vec![0x4];
        pt.extend_from_slice(&mut self.attestation_public_key());
        let group = EcGroup::new(EcGroupId::SecP256R1).map_err(|e| format_err!("Cannot create EcGroup: {}", e))?;
        let pt = EcPoint::from_binary(&group, &pt).map_err(|e| format_err!("Cannot create point from Quote header: {}", e))?;
        Pk::public_from_ec_components(group, pt).map_err(|e| format_err!("Cannot create pub key from Quote header: {}", e))
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

    pub fn certification_data<T: Qe3CertData<'a>>(&self) -> Result<T> {
        T::parse(self.certification_data_type, self.certification_data.clone())
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

    // verify signature against quote using attestation_public_key
    #[cfg(feature = "verify")]
    pub fn verify_quote_signature(&'a self, quote: &[u8]) -> Result<&'a Self> {
        let sig = get_ecdsa_sig_der(self.signature())?;
        let data = &quote[0..432]; // Quote Header + ISV Enclave Report
        let mut hash = [0u8; 32];
        Md::hash(hash::Type::Sha256, &data, &mut hash)?;
        let mut pk = self.attestation_pk()?;
        pk.verify(mbedtls::hash::Type::Sha256, &hash, &sig)?;

        Ok(self)
    }

    #[cfg(feature = "verify")]
    pub fn verify_qe3_report_signature(&self, pck_pk: &[u8]) -> Result<()> {
        //   verify QE report signature signed by pck
        let sig = get_ecdsa_sig_der(self.qe3_signature())?;
        let mut hash = [0u8; 32];
        println!("qe3_report binary: {:?}", self.qe3_report());
        println!("qe3_report len: {:?}", &self.qe3_report().len());
        Md::hash(hash::Type::Sha256, &self.qe3_report(), &mut hash)?;
        println!("qe3_report hash: {:?}", hash);
        let mut pck_pk = Pk::from_public_key(&pck_pk)?;
        let res = pck_pk.verify(mbedtls::hash::Type::Sha256, &hash, &sig);

        //   verify QE report::reportdata
        let mut qe3_report = Vec::with_capacity(Report::UNPADDED_SIZE);
        qe3_report.extend(self.qe3_report());
        qe3_report.resize_with(Report::UNPADDED_SIZE, Default::default);
        let qe3_report = Report::try_copy_from(&qe3_report).ok_or(format_err!("Could not construct Qe3 report"))?;
        println!("qe3_report: {:?}", qe3_report);

        println!("qe3_report.cpusvn: {:?}", qe3_report.cpusvn);
        println!("qe3_report.miscselect: {:?}", qe3_report.miscselect);
        println!("qe3_report._reserved1: {:?}", qe3_report._reserved1);
        println!("qe3_report.attributes: {:?}", qe3_report.attributes);
        println!("qe3_report.mrenclave: {:?}", qe3_report.mrenclave);
        println!("qe3_report._reserved2: {:?}", qe3_report._reserved2);
        println!("qe3_report.mrsigner: {:?}", qe3_report.mrsigner);
        println!("qe3_report._reserved3: {:?}", qe3_report._reserved3);
        println!("qe3_report.isvprodid: {:?}", qe3_report.isvprodid);
        println!("qe3_report.isvsvn: {:?}", qe3_report.isvsvn);
        println!("qe3_report._reserved4: {:?}", qe3_report._reserved4);
        println!("qe3_report.reportdata: {:?}", qe3_report.reportdata);
        println!("qe3_report.keyid: {:?}", qe3_report.keyid);
        println!("qe3_report.mac: {:?}", qe3_report.mac);
        println!("self.attestation_public_key: {:?}", self.attestation_public_key());
        println!("self.authentication_data: {:?}", self.authentication_data());
        let mut hash = [0u8; 32];
        let mut sha256 = Md::new(hash::Type::Sha256)?;
        sha256.update(self.attestation_public_key())?;
        sha256.update(self.authentication_data())?;
        sha256.finish(&mut hash)?;

        if qe3_report.reportdata[0..32] != hash {
            bail!("Verification of QE3 report data failed");
        }

        if qe3_report.reportdata[32..64] != [0; 32] {
            bail!("Verification of QE3 report data failed (second half not 0)");
        }

        res?;

        Ok(())
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

#[cfg(feature = "verify")]
pub trait Quote3SignatureEcdsaP256Verifier {
    /// Verify the platform certification data.
    ///
    /// The certification data is in `quote3signature.certification_data()`.
    ///
    /// On success, should return the platform certification public key (PCK) in DER format.
    // TODO: pass a container for the certification type and data instead of
    // the whole signature structure.
    fn verify_certification_data<'a>(&mut self, quote3signature: &'a Quote3SignatureEcdsaP256) -> Result<Vec<u8>>;

    /// Verify the quoting enclave (QE3).
    fn verify_qe3(&mut self, qe3_report: &[u8], authentication_data: &[u8]) -> Result<()>;
}

#[cfg(feature = "verify")]
pub trait Quote3SignatureVerify<'a>: Quote3Signature<'a> {
    type TrustRoot;

    fn verify(&self, quote: &[u8], root_of_trust: Self::TrustRoot) -> Result<()>;
}

#[cfg(feature = "verify")]
impl<'a> Quote3SignatureVerify<'a> for Quote3SignatureEcdsaP256<'a> {
    type TrustRoot = &'a mut dyn Quote3SignatureEcdsaP256Verifier;

    fn verify(&self, quote: &[u8], verifier: Self::TrustRoot) -> Result<()> {
        println!("Quote3SignatureVerify::verify verify_certification_data");
        let pck_pk = verifier.verify_certification_data(self)?;
        println!("Quote3SignatureVerify::verify verify_qe3_report_signature");
        self.verify_qe3_report_signature(&pck_pk)?;
        println!("Quote3SignatureVerify::verify verify_qe3");
        verifier.verify_qe3(self.qe3_report(), self.authentication_data())?;
        println!("Quote3SignatureVerify::verify verify_quote_signature");
        self.verify_quote_signature(quote)?;
        Ok(())
    }
}

impl<'a> Quote<'a> {
    #[cfg(feature = "verify")]
    pub fn verify<T: Quote3SignatureVerify<'a>>(quote: &'a [u8], root_of_trust: T::TrustRoot) -> Result<Self> {
        let parsed_quote = Self::parse(quote)?;
        let sig = parsed_quote.signature::<T>()?;
        Quote3SignatureVerify::verify(&sig, quote, root_of_trust)?;
        Ok(parsed_quote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "verify")]
    use mbedtls::x509::certificate::{Certificate};
    #[cfg(feature = "verify")]
    use std::ffi::CString;
    #[cfg(feature = "verify")]
    use serde::{Deserialize, Serialize};

    #[cfg(feature = "verify")]
    #[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Copy)]
    pub enum TcbStatus {
        UpToDate,
        SWHardeningNeeded,
        ConfigurationNeeded,
        ConfigurationAndSWHardeningNeeded,
        OutOfDate,
        OutOfDateConfigurationNeeded,
        Revoked,
    }

    #[cfg(feature = "verify")]
    #[derive(Clone, Serialize, Deserialize, Debug)]
    struct Tcb {
        isvsvn: u16,
    }

    #[cfg(feature = "verify")]
    #[serde(rename_all = "camelCase")]
    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct TcbLevel {
        tcb: Tcb,
        tcb_date: String,
        tcb_status: TcbStatus,
        #[serde(default, rename = "advisoryIDs", skip_serializing_if = "Vec::is_empty")]
        advisory_ids: Vec<String>,
    }

    #[cfg(feature = "verify")]
    #[serde(rename_all = "camelCase")]
    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct QeIdentity {
        version: u16,
        id: String,
        issue_date: String,
        next_update: String,
        tcb_evaluation_data_number: u32,
        miscselect: String,
        miscselect_mask: String,
        attributes: String,
        attributes_mask: String,
        mrsigner: String,
        isvprodid: u16,
        tcb_levels: Vec<TcbLevel>,
    }

    #[cfg(feature = "verify")]
    #[serde(rename_all = "camelCase")]
    #[derive(Deserialize)]
    struct QeIdentitySigned {
        enclave_identity: QeIdentity,
        _signature: String,
    }

    #[test]
    fn test_parse_certdata() {
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

    #[cfg(feature = "verify")]
    pub struct MyVerifier{
        qe3_identity: String,
    }

    #[cfg(feature = "verify")]
    impl Quote3SignatureEcdsaP256Verifier for MyVerifier {
        fn verify_certification_data<'a>(&mut self, quote3signature: &'a Quote3SignatureEcdsaP256) -> Result<Vec<u8>> {
            let certs = quote3signature.certification_data::<Qe3CertDataPckCertChain>().unwrap().certs;
            let pck = include_str!("../tests/pck_quote.cert");
            let processor_ca = include_str!("../tests/processor_ca.cert");
            let root_ca = include_str!("../tests/root_ca.cert");
            assert_eq!(certs[0], pck.trim());
            assert_eq!(certs[1], processor_ca.trim());
            assert_eq!(certs[2], root_ca.trim());
            assert_eq!(certs.len(), 3);

            let cert_chain = quote3signature.certification_data::<Qe3CertDataPckCertChain>()?;
            let pck = CString::new(cert_chain.certs[0].as_ref())?;
            let mut pck = Certificate::from_pem(pck.as_bytes_with_nul())?;
            Ok(pck.public_key_mut().write_public_der_vec()?)
        }

        /// Verify the quoting enclave (QE3).
        fn verify_qe3(&mut self, qe3_report: &[u8], authentication_data: &[u8]) -> Result<()> {
            assert_eq!(authentication_data,(0..=31).collect::<Vec<u8>>().as_slice());

            let mut report = Vec::with_capacity(Report::UNPADDED_SIZE);
            report.extend(qe3_report);
            report.resize_with(Report::UNPADDED_SIZE, Default::default);
            let report = Report::try_copy_from(&report).ok_or(format_err!("Could not construct Qe3 report"))?;

            let qe3_identity: QeIdentitySigned = serde_json::from_str(&self.qe3_identity).unwrap();
            if let Some(tcb_level) = qe3_identity.enclave_identity.tcb_levels.iter().find(|level| level.tcb.isvsvn == report.isvsvn) {
                if tcb_level.tcb_status == TcbStatus::UpToDate {
                    // WARNING: other features in the report also need to be verified
                    return Ok(())
                }
            }

            Err(format_err!("QE3 out of date"))
        }
    }

    #[test]
    fn test_quote_verification() {
        const TEST_QUOTE: &[u8] = &*include_bytes!("../tests/quote_pck_cert_chain.bin");
        let quote = Quote::parse(TEST_QUOTE).unwrap();
        let &QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ..
        } = quote.header();

        assert_eq!(qe3_vendor_id, &&QE3_VENDOR_ID_INTEL[..]);

        assert_eq!(attestation_key_type, Quote3AttestationKeyType::EcdsaP256);

        #[cfg(feature = "verify")]
        let mut verifier = MyVerifier {
            // The quote in `quote_pck_cert_chain.bin` is created with an out of date QE3 enclave.
            // Since we do not have an old, but matching `qe3_identity.json` file, a newer version
            // has been modified. This obviously will be detected when the signature in that file
            // is checked, but this is not implemented
            // TODO: Update the example quote with a matching qe3_identity.json file
            qe3_identity: include_str!("../tests/corrupt_qe3_identity.json").to_string(),
        };
        #[cfg(feature = "verify")]
        assert!(Quote::verify::<Quote3SignatureEcdsaP256>(TEST_QUOTE, &mut verifier).is_ok())
    }

    #[test]
    fn test_quote_verification_qe3_out_of_date() {
        const TEST_QUOTE: &[u8] = &*include_bytes!("../tests/quote_pck_cert_chain.bin");
        let quote = Quote::parse(TEST_QUOTE).unwrap();
        let &QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ..
        } = quote.header();

        assert_eq!(qe3_vendor_id, &&QE3_VENDOR_ID_INTEL[..]);

        assert_eq!(attestation_key_type, Quote3AttestationKeyType::EcdsaP256);

        #[cfg(feature = "verify")]
        let mut verifier = MyVerifier {
            qe3_identity: include_str!("../tests/qe3_identity.json").to_string(),
        };
        #[cfg(feature = "verify")]
        assert!(Quote::verify::<Quote3SignatureEcdsaP256>(TEST_QUOTE, &mut verifier).is_err())
    }

    #[test]
    fn test_corrupt_quote_verification() {
        const TEST_QUOTE: &[u8] = &*include_bytes!("../tests/quote_pck_cert_chain_corrupted.bin");
        let quote = Quote::parse(TEST_QUOTE).unwrap();
        let &QuoteHeader::V3 {
            attestation_key_type,
            ref qe3_vendor_id,
            ..
        } = quote.header();

        assert_eq!(qe3_vendor_id, &&QE3_VENDOR_ID_INTEL[..]);

        assert_eq!(attestation_key_type, Quote3AttestationKeyType::EcdsaP256);

        #[cfg(feature = "verify")]
        let mut verifier = MyVerifier {
            // The quote in `quote_pck_cert_chain.bin` is created with an out of date QE3 enclave.
            // Unfortunately, we do not have a matching `qe3_identity.json` file and the QE3 TCB
            // state is verified before the PCK cert chain is verified. As the test verifier does
            // not check the signature in `qe3_identity.json` we can modify it for test purposes.
            // TODO Update the example quote with a matching QE3 identity file
            qe3_identity: include_str!("../tests/corrupt_qe3_identity.json").to_string(),
        };
        #[cfg(feature = "verify")]
        assert!(Quote::verify::<Quote3SignatureEcdsaP256>(TEST_QUOTE, &mut verifier).is_err());
    }
}
