/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use std::borrow::Cow;
use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
use std::fmt::Debug;
use std::mem;
use std::path::PathBuf;

use percent_encoding::percent_decode;
use pkix::pem::{self, PEM_CERTIFICATE};
use pkix::types::ObjectIdentifier;
use pkix::x509::GenericCertificate;
use pkix::FromBer;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sgx_pkix::oid::{self, SGX_EXTENSION};
use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, BERReaderSeq};
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::{Box as MbedtlsBox, List as MbedtlsList},
    mbedtls::ecp::EcPoint,
    mbedtls::x509::certificate::Certificate,
    mbedtls::error::{codes, Error as ErrMbed},
    std::ffi::CString,
    std::ops::Deref,
    super::{DcapArtifactIssuer, PckCrl},
};

use crate::io::{self, WriteOptions};
use crate::tcb_info::{Fmspc, TcbData, TcbLevel};
use crate::{CpuSvn, Error, PlatformTypeForTcbInfo, Unverified, VerificationType, Verified, platform};

/// [`SGXType`] is a rust enum representing the Intel® SGX Type.
///
/// Ref: <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf>
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum SGXType {
    Standard,
    /// Type for machines only provide confidentiality protection for EPC memory, such as Azure DC v3 instance.
    Scalable,
    /// Type for machines provide integrity and confidentiality protection for EPC memory, such as our FX2200 series 3 instance.
    ScalableWithIntegrity,
}

impl Default for SGXType {
    fn default() -> SGXType {
        SGXType::Standard
    }
}

impl TryFrom<i64> for SGXType {
    type Error = ();

    fn try_from(v: i64) -> Result<Self, ()> {
        match v {
            0 => Ok(SGXType::Standard),
            1 => Ok(SGXType::Scalable),
            2 => Ok(SGXType::ScalableWithIntegrity),
            _ => Err(()),
        }
    }
}

/// TCB component as specified in the Intel PCKCrt API v3 and v4
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TcbComponentsV3 {
    sgxtcbcomp01svn: u8,
    sgxtcbcomp02svn: u8,
    sgxtcbcomp03svn: u8,
    sgxtcbcomp04svn: u8,
    sgxtcbcomp05svn: u8,
    sgxtcbcomp06svn: u8,
    sgxtcbcomp07svn: u8,
    sgxtcbcomp08svn: u8,
    sgxtcbcomp09svn: u8,
    sgxtcbcomp10svn: u8,
    sgxtcbcomp11svn: u8,
    sgxtcbcomp12svn: u8,
    sgxtcbcomp13svn: u8,
    sgxtcbcomp14svn: u8,
    sgxtcbcomp15svn: u8,
    sgxtcbcomp16svn: u8,
    pcesvn: u16,
}

/// TCB component as specified in TcbInfo (version 3) of the PCS version 4 API
/// https://api.trustedservices.intel.com/documents/PCS_V3-V4_migration_guide.pdf
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TcbComponentEntry {
    svn: u8,
    #[serde(default)]
    category: String,
    #[serde(default, rename = "type")]
    comp_type: String,
}

impl From<u8> for TcbComponentEntry {
    fn from(svn: u8) -> TcbComponentEntry {
        TcbComponentEntry {
            svn,
            category: String::new(),
            comp_type: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct SGXSpecificTcbComponentData {}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TDXSpecificTcbComponentData {
    pub(crate) tdxtcbcomponents: [TcbComponentEntry; 16],
}

pub trait PlatformTypeForTcbComponent
where
    // This bound ensures that the type-checker understands that `TcbComponents` implements
    // `TryFrom`, since a normal where-bound would not be propagated
    Self: ImplyBound<ToBound = TcbComponents<Self::PlatformSpecificTcbComponentData>>,
    Self: ImplyBound<ToBound: TryFrom<TcbComponentsV3, Error = Error>>,
{
    type PlatformSpecificTcbComponentData: Debug
        + Clone
        + Serialize
        + DeserializeOwned;
}

impl PlatformTypeForTcbComponent for platform::SGX {
    type PlatformSpecificTcbComponentData = SGXSpecificTcbComponentData;
}

impl PlatformTypeForTcbComponent for platform::TDX {
    type PlatformSpecificTcbComponentData = TDXSpecificTcbComponentData;
}

/// Auxiliary trait to propagate bound on
/// [PlatformTypeForTcbComponent::PlatformSpecificTcbComponentData]
pub trait ImplyBound where Self: Sized {
    type ToBound;
}

impl ImplyBound for platform::SGX {
    type ToBound = TcbComponents<SGXSpecificTcbComponentData>;
}

impl ImplyBound for platform::TDX {
    type ToBound = TcbComponents<TDXSpecificTcbComponentData>;
}

impl TryFrom<TcbComponentsV3> for TcbComponents<SGXSpecificTcbComponentData> {
    type Error = Error;

    fn try_from(value: TcbComponentsV3) -> Result<Self, Error> {
        Ok(TcbComponents::<SGXSpecificTcbComponentData>(value.into()))
    }
}

impl TryFrom<TcbComponentsV3> for TcbComponents<TDXSpecificTcbComponentData> {
    type Error = Error;

    fn try_from(_value: TcbComponentsV3) -> Result<Self, Error> {
        Err(Error::InvalidTcbInfo("attempting to convert TcbComponentsV3 into TcbComponentsV4<TDX>".to_string()))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcbComponentsV4<P> {
    sgxtcbcomponents: [TcbComponentEntry; 16],
    pcesvn: u16,
    #[serde(flatten)]
    platform_specific_data: P,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum TcbComponentsCompatibilitySelector<P> {
    V3(TcbComponentsV3),
    V4(TcbComponentsV4<P>),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq)]
#[serde(try_from = "TcbComponentsCompatibilitySelector<P>")]
#[serde(bound(deserialize = "TcbComponents<P>: TryFrom<TcbComponentsV3, Error: std::fmt::Display>, P : Deserialize<'de>"))]
pub struct TcbComponents<P>(TcbComponentsV4<P>);

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum TcbComponentType {
    EarlyMicrocodeUpdate,
    LateMicrocodeUpdate,
}

impl TryFrom<&str> for TcbComponentType {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s == "Early Microcode Update" {
            Ok(TcbComponentType::EarlyMicrocodeUpdate)
        } else if s == "SGX Late Microcode Update" {
            Ok(TcbComponentType::LateMicrocodeUpdate)
        } else {
            Err(())
        }
    }
}

impl TcbComponents<SGXSpecificTcbComponentData> {
    pub fn from_raw(raw_cpusvn: [u8; 16], pcesvn: u16) -> Self {
        TcbComponents(TcbComponentsV4 {
            sgxtcbcomponents: raw_cpusvn.map(|svn| svn.into()),
            pcesvn,
            platform_specific_data: SGXSpecificTcbComponentData {}
        })
    }
}

impl TcbComponents<TDXSpecificTcbComponentData> {
    pub fn from_raw(raw_cpusvn: [u8; 16], pcesvn: u16, raw_tdxsvn: [u8; 16]) -> Self {
        TcbComponents (TcbComponentsV4 {
            sgxtcbcomponents: raw_cpusvn.map(|svn| svn.into()),
            pcesvn,
            platform_specific_data: TDXSpecificTcbComponentData {
                tdxtcbcomponents: raw_tdxsvn.map(|tdxsvn| tdxsvn.into())
            }
        })
    }

    pub fn tdx_tcb_components(&self) -> &[TcbComponentEntry; 16] {
        &self.0.platform_specific_data.tdxtcbcomponents
    }
}

impl<P> TcbComponents<P> {
    fn iter_components<'a>(&'a self) -> impl Iterator<Item = u16> + 'a {
        self.0
            .sgxtcbcomponents
            .iter()
            .map(|comp| comp.svn as u16)
            .chain(std::iter::once(self.0.pcesvn))
    }

    pub fn pce_svn(&self) -> u16 {
        self.0.pcesvn
    }

    pub fn cpu_svn(&self) -> CpuSvn {
        // NOTE: to support older stable compilers (pre 1.77) we are avoiding
        // the obvious implementation:
        //
        // self.0.sgxtcbcomponents.each_ref().map(|c| c.svn)
        let mut out: CpuSvn = [0u8; 16];
        for (i, c) in self.0.sgxtcbcomponents.iter().enumerate() {
            out[i] = c.svn;
        }
        out
    }

    /// Returns the index of the TCB component
    pub fn tcb_component_index(&self, comp: TcbComponentType) -> Option<usize> {
        self.0.sgxtcbcomponents
            .iter()
            .position(|c| TcbComponentType::try_from(c.comp_type.as_str()) == Ok(comp))
    }
}

impl<T, U> PartialOrd<TcbComponents<U>> for TcbComponents<T> {
    /// Compare all 17 components. If all are equal, order as equal. If some
    /// are less and others are greater, ordering is not defined. If some are
    /// less, order as less. If some are greater, order as greater.
    fn partial_cmp(&self, other: &TcbComponents<U>) -> Option<Ordering> {
        let mut prev: Option<Ordering> = None;

        for (a, b) in self.iter_components().zip(other.iter_components()) {
            match (a.cmp(&b), prev) {
                (x, None) | (x, Some(Ordering::Equal)) => prev = Some(x),
                (Ordering::Greater, Some(Ordering::Less)) | (Ordering::Less, Some(Ordering::Greater)) => return None,
                (Ordering::Equal, Some(Ordering::Less))
                | (Ordering::Equal, Some(Ordering::Greater))
                | (Ordering::Less, Some(Ordering::Less))
                | (Ordering::Greater, Some(Ordering::Greater)) => (),
            }
        }
        prev
    }
}

impl<T, U> PartialEq<TcbComponents<U>> for TcbComponents<T> {
    fn eq(&self, other: &TcbComponents<U>) -> bool {
        for (a, b) in self.iter_components().zip(other.iter_components()) {
            if a != b {
                return false;
            }
        }
        true
    }
}

impl std::convert::From<TcbComponentsV3> for TcbComponentsV4<SGXSpecificTcbComponentData> {
    fn from(c: TcbComponentsV3) -> Self {
        TcbComponentsV4 {
            sgxtcbcomponents: [
                c.sgxtcbcomp01svn.into(),
                c.sgxtcbcomp02svn.into(),
                c.sgxtcbcomp03svn.into(),
                c.sgxtcbcomp04svn.into(),
                c.sgxtcbcomp05svn.into(),
                c.sgxtcbcomp06svn.into(),
                c.sgxtcbcomp07svn.into(),
                c.sgxtcbcomp08svn.into(),
                c.sgxtcbcomp09svn.into(),
                c.sgxtcbcomp10svn.into(),
                c.sgxtcbcomp11svn.into(),
                c.sgxtcbcomp12svn.into(),
                c.sgxtcbcomp13svn.into(),
                c.sgxtcbcomp14svn.into(),
                c.sgxtcbcomp15svn.into(),
                c.sgxtcbcomp16svn.into(),
            ],
            pcesvn: c.pcesvn,
            platform_specific_data: SGXSpecificTcbComponentData {}
        }
    }
}

impl<P> TryFrom<TcbComponentsCompatibilitySelector<P>> for TcbComponents<P>
where
    TcbComponents<P>: TryFrom<TcbComponentsV3>,
{
    type Error = <TcbComponents<P> as TryFrom<TcbComponentsV3>>::Error;

    fn try_from(c: TcbComponentsCompatibilitySelector<P>) -> Result<Self, Self::Error> {
        match c {
            TcbComponentsCompatibilitySelector::V3(c) => c.try_into(),
            TcbComponentsCompatibilitySelector::V4(c) => Ok(TcbComponents(c)),
        }
    }
}

impl<T> std::convert::From<TcbComponentsV4<T>> for TcbComponents<T> {
    fn from(tcb_components: TcbComponentsV4<T>) -> Self {
        TcbComponents::<T>(tcb_components)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PckCertValue {
    Cert(Vec<u8>),
    Missing(String),
}

impl<'de> Deserialize<'de> for PckCertValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let der = percent_decode(s.as_bytes())
            .decode_utf8()
            .map_err(|_| Error::InvalidPcks("utf8 decode error".into()))
            .map(|c| pem::pem_to_der(c.trim(), Some(PEM_CERTIFICATE)));

        if let Ok(Some(der)) = der {
            Ok(PckCertValue::Cert(der))
        } else {
            Ok(PckCertValue::Missing(s.to_string()))
        }
    }
}

impl Serialize for PckCertValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PckCertValue::Cert(der) => serializer.serialize_str(&pem::der_to_pem(der, PEM_CERTIFICATE)),
            PckCertValue::Missing(s) => serializer.serialize_str(s),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PckCertBodyItem {
    tcb: TcbComponents<SGXSpecificTcbComponentData>,
    tcbm: String,
    cert: PckCertValue,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PckCerts {
    pck_data: Vec<PckCertBodyItem>,
    ca_chain: Vec<String>,
}

impl PckCerts {
    pub fn new(pck_data: Vec<PckCertBodyItem>, ca_chain: Vec<String>) -> Self {
        Self { pck_data, ca_chain }
    }

    pub fn parse(body: &str, ca_chain: Vec<String>) -> Result<PckCerts, Error> {
        let data: Vec<PckCertBodyItem> = serde_json::from_str(body)?;

        let pcks = PckCerts {
            pck_data: data,
            ca_chain,
        };
        Ok(pcks)
    }

    pub fn filename(qe_id: &[u8]) -> String {
        format!("{}.certs", base16::encode_lower(qe_id))
    }

    pub fn write_to_file(&self, output_dir: &str, qe_id: &[u8], option: WriteOptions) -> Result<Option<PathBuf>, Error> {
        let filename = PckCerts::filename(qe_id);
        io::write_to_file(&self, output_dir, &filename, option)
    }

    pub fn read_from_file(input_dir: &str, qe_id: &[u8]) -> Result<Self, Error> {
        let filename = PckCerts::filename(qe_id);
        let pcks: PckCerts = io::read_from_file(input_dir, &filename)?;
        Ok(pcks)
    }

    pub fn fmspc(&self) -> Result<Fmspc, Error> {
        let pck = self.iter().nth(0).ok_or(Error::NoPckCertData)?;
        let sgx_extension = SGXPCKCertificateExtension::try_from(pck).map_err(|e| Error::InvalidPckFormat(e))?;
        Ok(sgx_extension.fmspc)
    }

    pub fn ca_chain(&self) -> &[String] {
        &self.ca_chain
    }

    /// Returns an iterator over the pck certificates (in der format) in this structure.
    /// WARNING: Missing, or malformed certificates are hidden from the iterator
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.pck_data.iter().filter_map(|pck_body_item| {
            if let PckCertValue::Cert(der) = &pck_body_item.cert {
                Some(der)
            } else {
                None
            }
        })
    }

    /// Returns a `Vec` of `PckCert` in this structure.
    /// WARNING: Missing, or malformed certificates are hidden from the iterator
    pub fn as_pck_certs(&self) -> Vec<PckCert<Unverified>> {
        self.iter()
            .map(|pckcert| PckCert::new(pem::der_to_pem(pckcert, PEM_CERTIFICATE), self.ca_chain.clone()))
            .collect()
    }

    /// Order all PCKs according to the tcb info
    /// TCB Info is carefully ordered by Intel
    fn order_pcks<T: PlatformTypeForTcbInfo, V: VerificationType>(&self, tcb_info: &TcbData<T, V>) -> Vec<PckCert<Unverified>> {
        let mut pck_certs = self.as_pck_certs();

        // Sort PCK certs by applicable TCB level. If two certs are in the same TCB
        // level, maintain existing ordering (stable sort). PCK certs without a TCB
        // level are sorted last.
        pck_certs.sort_by_cached_key(|cert| cert.find_tcb_level_idx(tcb_info).unwrap_or(usize::max_value()));
        pck_certs
    }

    /// Given the cpusvn, pcesvn and qe_id, searches for the best PCK certificate
    /// Code re-implements <https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/ab8d31d72f842adb4b8a49eb3639f2e9a789d13b/tools/PCKCertSelection/PCKCertSelectionLib/pck_sorter.cpp#L441>
    pub fn select_pck<T: PlatformTypeForTcbInfo, V: VerificationType>(
        &self,
        tcb_info: &TcbData<T, V>,
        cpusvn: &[u8; 16],
        pcesvn: u16,
        pceid: u16,
    ) -> Result<PckCert<Unverified>, Error> {
        // 1. Order PCK certs according to TCB levels
        let pcks = self.order_pcks(&tcb_info);

        // 2. Find first PCK cert in ordered list that matches current platform
        let tcb_components = tcb_info.decompose_raw_cpusvn(cpusvn, pcesvn)?;
        let pck = pcks
            .iter()
            .find(|pck| pck.valid_for_tcb(&tcb_components, pceid).is_ok())
            .ok_or(Error::NoPckForTcbFound)?;
        Ok(pck.to_owned())
    }

    #[cfg(feature = "verify")]
    pub fn issuer(&self) -> Option<DcapArtifactIssuer> {
        self.iter()
            .find_map(|pckcert| {
                let pck = PckCert::new(pem::der_to_pem(pckcert, PEM_CERTIFICATE), self.ca_chain.clone());
                pck.issuer().ok()
            })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PckCert<V: VerificationType = Verified> {
    cert: String,
    ca_chain: Vec<String>,
    type_: V,
}

impl PckCert<Unverified> {
    pub fn from_pck_chain(certs: Vec<Cow<'_, str>>) -> Result<PckCert<Unverified>, Error> {
        if certs.is_empty() {
            return Err(Error::InvalidPck("Missing CA chain".into()));
        }
        if let Some((first, rest)) = certs.split_first() {
            Ok(PckCert::new(first.to_string(), rest.iter().map(|c| c.to_string()).collect()))
        } else {
            Err(Error::InvalidPck("Expected two certificates in CA chain".into()))
        }
    }

    /// Creates a new PckCert from the PCK certificate and CA chain. The root certificate must be
    /// the last certificate in the chain
    pub fn new(cert: String, ca_chain: Vec<String>) -> PckCert<Unverified> {
        let ca_chain = ca_chain.iter().map(|cert| cert.trim().to_string()).collect();
        PckCert {
            cert,
            ca_chain,
            type_: Unverified
        }
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(self, trusted_root_certs: &[B], pckcrl: Option<&str>) -> Result<PckCert, Error> {
        let mut crl = if let Some(pckcrl) = pckcrl {
            let pckcrl = PckCrl::new(pckcrl.to_string(), self.ca_chain.clone())?;
            let pckcrl = pckcrl.verify(trusted_root_certs)?;
            Some(pckcrl.as_mbedtls_crl()?)
        } else {
            None
        };

        let pck = CString::new(self.cert.as_bytes()).map_err(|_| Error::InvalidPck("Conversion into CString failed".into()))?;
        let pck = Certificate::from_pem(pck.as_bytes_with_nul())
            .map_err(|_| Error::InvalidPck("Cannot decode PCKCert as pem".into()))?;

        let (mut chain, root) = crate::create_cert_chain(&self.ca_chain)?;
        chain.insert(0, pck);
        let trust_ca: MbedtlsList<Certificate> = chain.into_iter().collect();
        let root_list = std::iter::once(root).collect();
        let mut err = String::default();
        Certificate::verify(&trust_ca, &root_list, crl.as_mut(), Some(&mut err))
            .map_err(|_| Error::InvalidPck(format!("Failed to verify PckCert: {}", err)))?;

        crate::check_root_ca(trusted_root_certs, &root_list)?;

        Ok(PckCert {
            cert: self.cert,
            ca_chain: self.ca_chain,
            type_: Verified,
        })
    }

    #[cfg(feature = "verify")]
    pub fn issuer(&self) -> Result<DcapArtifactIssuer, Error> {
        let pck = CString::new(self.cert.as_bytes()).map_err(|e| Error::InvalidPck(e.to_string()))?;
        let pck = Certificate::from_pem(pck.as_bytes_with_nul()).map_err(|e| Error::InvalidPck(e.to_string()))?;
        let issuer = pck.issuer().map_err(|e| Error::InvalidPck(e.to_string()))?;

        DcapArtifactIssuer::try_from(issuer.as_str())
    }

    pub fn read_from_file(input_dir: &str, filename: &str) -> Result<Self, Error> {
        io::read_from_file(input_dir, filename)
    }
}

impl PckCert<Verified> {
    /// Selects the highest matching TCB level
    /// see <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v2>
    pub fn find_tcb_state<V: VerificationType, T: PlatformTypeForTcbInfo>(
        &self,
        tcb_data: &TcbData<T, V>,
    ) -> Option<TcbLevel<T::PlatformSpecificTcbComponentData>> {
        let idx = self.find_tcb_level_idx(tcb_data)?;
        Some(tcb_data.tcb_levels()[idx].clone())
    }

    #[cfg(feature = "verify")]
    pub fn pck(&self) -> Result<MbedtlsBox<Certificate>, ErrMbed> {
        let cert = CString::new(self.cert.as_bytes()).map_err(|_| ErrMbed::HighLevel(codes::X509InvalidFormat))?;
        Certificate::from_pem(cert.as_bytes_with_nul()).map_err(|_| ErrMbed::HighLevel(codes::X509InvalidFormat))
    }

    #[cfg(feature = "verify")]
    pub fn public_key(&self) -> Result<EcPoint, ErrMbed> {
        let cert = self.pck()?;
        let pk = cert.public_key();
        pk.ec_public()
    }

    pub fn ppid(&self) -> Result<Vec<u8>, ASN1Error> {
        let extension = self.sgx_extension()?;
        Ok(extension.ppid)
    }

    pub fn fmspc(&self) -> Result<Fmspc, ASN1Error> {
        let extension = self.sgx_extension()?;
        Ok(extension.fmspc)
    }
}

impl<V: VerificationType> PckCert<V> {
    /// Returns the the CA chain in the order [leaf .. root]
    pub fn ca_chain(&self) -> &[String] {
        return &self.ca_chain;
    }

    pub fn pck_pem<'a>(&'a self) -> &'a String {
        &self.cert
    }

    pub fn write_to_file(&self, output_dir: &str, filename: &str, option: WriteOptions) -> Result<Option<PathBuf>, Error> {
        io::write_to_file(&self, output_dir, &filename, option)
    }

    pub fn sgx_extension(&self) -> Result<SGXPCKCertificateExtension, ASN1Error> {
        let der = &pem::pem_to_der(&self.cert, Some(PEM_CERTIFICATE)).ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let cert = GenericCertificate::from_ber(&der)?;
        let extension = cert
            .tbscert
            .get_extension(&SGX_EXTENSION)
            .ok_or(ASN1Error::new(ASN1ErrorKind::Eof))?;
        SGXPCKCertificateExtension::parse_extension(&extension.value)
    }

    pub fn platform_tcb(&self) -> Result<PlatformTCB, ASN1Error> {
        let extension = self.sgx_extension()?;
        Ok(extension.tcb)
    }

    fn as_pck_cert_body_item(&self) -> Result<PckCertBodyItem, ASN1Error> {
        let ext = self.sgx_extension()?;
        let cpusvn = ext.tcb.cpusvn;
        let pce_svn = ext.tcb.tcb_components.0.pcesvn;
        let mut tcbm = Vec::from(cpusvn);
        tcbm.extend_from_slice(&pce_svn.to_le_bytes());
        let cert = pem::pem_to_der(&self.cert, Some(PEM_CERTIFICATE)).ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        Ok(PckCertBodyItem {
            tcb: ext.tcb.tcb_components,
            tcbm: base16::encode_upper(&tcbm),
            cert: PckCertValue::Cert(cert),
        })
    }

    pub fn sgx_type(&self) -> Result<SGXType, ASN1Error> {
        let extension = self.sgx_extension()?;
        Ok(extension.sgx_type)
    }

    /// Find the index of the highest matching TCB level
    fn find_tcb_level_idx<V2: VerificationType, T: PlatformTypeForTcbInfo>(&self, tcb_info: &TcbData<T, V2>) -> Option<usize> {
        // Go over the sorted collection of TCB Levels retrieved from TCB Info starting from the first item on the list:
        //   1. Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16) with the corresponding
        //      values in the TCB Level. If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values
        //      in TCB Level, go to 3.b, otherwise move to the next item on TCB Levels list.
        //   2. Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value in the TCB Level. If it is
        //      greater or equal to the value in TCB Level, read status assigned to this TCB level. Otherwise, move to the next item
        //      on TCB Levels list.
        // If no TCB level matches your SGX PCK Certificate, your TCB Level is not supported.
        let pck_tcb_level = self.platform_tcb().ok()?;
        tcb_info
            .tcb_levels()
            .iter()
            .position(|tcb| *tcb.components() <= pck_tcb_level.tcb_components)
    }

    fn valid_for_tcb(&self, comps: &TcbComponents<SGXSpecificTcbComponentData>, pceid: u16) -> Result<(), Error> {
        let sgx_extension = self
            .sgx_extension()
            .map_err(|_| Error::InvalidPck("Failed to parse SGX extension".into()))?;
        let tcb = sgx_extension.tcb;
        if sgx_extension.pceid == pceid && tcb.tcb_components <= *comps {
            Ok(())
        } else {
            Err(Error::InvalidPck("PckCert isn't valid for provided TCB".into()))
        }
    }
}

#[derive(Default, Debug)]
pub struct PlatformTCB {
    pub tcb_components: TcbComponents<SGXSpecificTcbComponentData>,
    pub cpusvn: CpuSvn,
}

fn decode_tcb_sequence<'a, 'b>(reader: &mut BERReaderSeq<'a, 'b>) -> ASN1Result<PlatformTCB> {
    let mut platform_tcb = PlatformTCB::default();
    for i in 1..=18 {
        platform_tcb = reader.next().read_sequence(|reader| {
            let oid = reader.next().read_oid()?;
            if let Some((last, rest)) = oid.components().split_last() {
                if rest != oid::SGX_EXTENSION_TCB.components().as_slice() || i != *last {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                match last {
                    i @ 1..=16 => {
                        platform_tcb.tcb_components.0.sgxtcbcomponents[(i - 1) as usize].svn = reader.next().read_u8()?
                    }
                    17 => platform_tcb.tcb_components.0.pcesvn = reader.next().read_u16()?,
                    18 => {
                        platform_tcb.cpusvn = reader
                            .next()
                            .read_bytes()?
                            .as_slice()
                            .try_into()
                            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?
                    }
                    _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
                }
                Ok(platform_tcb)
            } else {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
        })?;
    }
    Ok(platform_tcb)
}

fn decode_ber_sgx_type(reader: BERReader) -> ASN1Result<SGXType> {
    reader
        .read_enum()?
        .try_into()
        .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
}

#[derive(Default, Debug)]
pub struct SGXPlatformConfiguration {
    pub dynamic: bool,
    pub cached_keys: bool,
    pub smt_enabled: bool,
}

fn read_tagged<'a, 'b, F, T>(reader: BERReader<'a, 'b>, oid: &ObjectIdentifier, callback: F) -> ASN1Result<T>
where
    F: for<'c> FnOnce(BERReader<'a, 'c>) -> ASN1Result<T>,
{
    reader.read_sequence(|reader| {
        if reader.next().read_oid()? != *oid {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        callback(reader.next())
    })
}

impl BERDecodable for SGXPlatformConfiguration {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let dynamic = read_tagged(reader.next(), &*oid::SGX_EXTENSION_CONF_DYNAMIC_PLATFORM, |r| r.read_bool())?;
            let cached_keys = read_tagged(reader.next(), &*oid::SGX_EXTENSION_CONF_CACHED_KEYS, |r| r.read_bool())?;
            let smt_enabled = read_tagged(reader.next(), &*oid::SGX_EXTENSION_CONF_SMT_ENABLED, |r| r.read_bool())?;

            Ok(SGXPlatformConfiguration {
                dynamic,
                cached_keys,
                smt_enabled,
            })
        })
    }
}

#[derive(Debug)]
pub struct SGXPCKCertificateExtension {
    pub ppid: Vec<u8>,
    pub tcb: PlatformTCB,
    pub pceid: u16,
    pub fmspc: Fmspc,
    pub sgx_type: SGXType,
    pub platform_instance_id: Option<Vec<u8>>,
    pub configuration: Option<SGXPlatformConfiguration>,
}

impl SGXPCKCertificateExtension {
    /// Parses an SGX PCK Certificate extension as define in Section 3.5
    /// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>
    pub fn parse_extension(extension: &[u8]) -> ASN1Result<Self> {
        yasna::parse_der(extension, |reader| {
            reader.read_sequence(|reader| {
                struct SGXPCKCertificateExtensionReader<'r, 'a, 'c> {
                    reader: &'r mut yasna::BERReaderSeq<'a, 'c>,
                    current: u64,
                }

                impl<'r, 'a, 'c> SGXPCKCertificateExtensionReader<'r, 'a, 'c> {
                    fn next<F, R>(&mut self, with_next: F) -> ASN1Result<R>
                    where
                        F: FnOnce(yasna::BERReader) -> ASN1Result<R>,
                    {
                        let current = &mut self.current;
                        self.reader.next().read_sequence(|reader| {
                            if let Some((last, comp)) = reader.next().read_oid()?.components().split_last() {
                                if *comp == *oid::SGX_EXTENSION.components().as_slice() && *current == *last {
                                    *current += 1;
                                    return with_next(reader.next());
                                }
                            }
                            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                        })
                    }
                }

                let mut reader = SGXPCKCertificateExtensionReader { reader, current: 1 };

                let ppid = reader.next(|reader| reader.read_bytes())?;
                let tcb = reader.next(|reader| reader.read_sequence(|reader| decode_tcb_sequence(reader)))?;
                let pceid = reader.next(|reader| reader.read_bytes())?;
                let fmspc = reader.next(|reader| reader.read_bytes())?;
                let sgx_type = reader.next(|reader| decode_ber_sgx_type(reader))?;

                let mut platform_instance_id = None;
                let mut configuration = None;
                if sgx_type == SGXType::Scalable || sgx_type == SGXType::ScalableWithIntegrity {
                    platform_instance_id = Some(reader.next(|reader| reader.read_bytes())?);
                    configuration = Some(reader.next(|reader| SGXPlatformConfiguration::decode_ber(reader))?);
                }

                let fmspc = Fmspc::try_from(&fmspc).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                if ppid.len() != 16 || pceid.len() != 2 || platform_instance_id.as_ref().map_or(false, |id| id.len() != 16) {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }

                let extension = SGXPCKCertificateExtension {
                    ppid,
                    tcb,
                    pceid: u16::from_be_bytes(pceid.as_slice().try_into().expect("validated len = 2")),
                    fmspc,
                    sgx_type,
                    configuration,
                    platform_instance_id,
                };

                Ok(extension)
            })
        })
    }
}

impl TryFrom<&str> for SGXPCKCertificateExtension {
    type Error = ASN1Error;

    fn try_from(cert: &str) -> Result<Self, ASN1Error> {
        let cert = &pem::pem_to_der(cert, Some(PEM_CERTIFICATE)).ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        SGXPCKCertificateExtension::try_from(cert)
    }
}

impl TryFrom<&Vec<u8>> for SGXPCKCertificateExtension {
    type Error = ASN1Error;

    fn try_from(cert: &Vec<u8>) -> Result<Self, ASN1Error> {
        let cert = GenericCertificate::from_ber(&cert)?;
        let extension = cert
            .tbscert
            .get_extension(&SGX_EXTENSION)
            .ok_or(ASN1Error::new(ASN1ErrorKind::Eof))?;
        SGXPCKCertificateExtension::parse_extension(&extension.value)
    }
}

impl<V> TryFrom<PckCert<V>> for PckCerts
where
    V: VerificationType,
{
    type Error = ASN1Error;

    fn try_from(pck: PckCert<V>) -> Result<PckCerts, ASN1Error> {
        let cert_body_item = pck.as_pck_cert_body_item()?;

        Ok(PckCerts {
            pck_data: vec![cert_body_item],
            ca_chain: pck.ca_chain,
        })
    }
}

/// NOTE: This conversion is only correct if all PCK certs in the vec have the
/// same CA chain.
impl<V> TryFrom<Vec<PckCert<V>>> for PckCerts
where
    V: VerificationType,
{
    type Error = ASN1Error;

    fn try_from(mut pcks: Vec<PckCert<V>>) -> Result<PckCerts, ASN1Error> {
        let pck_data = pcks.iter().map(|pck| pck.as_pck_cert_body_item()).collect::<Result<Vec<_>, ASN1Error>>()?;
        // NOTE: assuming that all PCK certs in the vec have the same CA chain,
        // so we pick the ca_chain from the first one:
        let ca_chain = match pcks.first_mut() {
            Some(first) => mem::take(&mut first.ca_chain),
            None => return Err(ASN1Error::new(ASN1ErrorKind::Eof)),
        };
        Ok(PckCerts { pck_data, ca_chain })
    }
}

#[cfg(test)]
mod tests {
    use dcap_ql::quote::{Qe3CertDataPckCertChain, Quote, Quote3SignatureEcdsaP256};
    use hex::FromHex;
    use pkix::derives::ObjectIdentifier;
    use sgx_pkix::oid::{SGX_EXTENSION_PPID, SGX_EXTENSION_TCB, SGX_EXTENSION_TCB_COMP01_SVN};
    use yasna;

    use super::*;
    #[cfg(not(target_env = "sgx"))]
    use crate::{get_cert_subject, get_cert_subject_from_der};

    fn decode_tcb_item<'a, 'b>(reader: &mut BERReaderSeq<'a, 'b>) -> ASN1Result<(ObjectIdentifier, u8)> {
        let oid = reader.next().read_oid()?;
        let value = reader.next().read_u8()?;
        Ok((oid, value))
    }

    #[test]
    fn sgx_extension_oid() {
        let oid_enc = vec![0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x01];

        let oid = yasna::parse_der(&oid_enc, |reader| {
            let oid = reader.read_oid()?;
            Ok(oid)
        })
        .unwrap();
        assert_eq!(oid, *SGX_EXTENSION_PPID);
    }

    #[test]
    fn sgx_extension_ppid() {
        let ppid_enc = vec![
            0x04, 0x10, 0x88, 0x58, 0x9d, 0xd5, 0x8b, 0xd4, 0xe8, 0x0c, 0x2b, 0x12, 0x49, 0x86, 0x22, 0xa3, 0x48, 0x77,
        ];

        let ppid = yasna::parse_der(&ppid_enc, |reader| {
            let ppid = reader.read_bytes()?;
            Ok(ppid)
        })
        .unwrap();
        assert_eq!(
            ppid,
            vec![136, 88, 157, 213, 139, 212, 232, 12, 43, 18, 73, 134, 34, 163, 72, 119]
        );
    }

    #[test]
    fn sgx_extension_ppid_seq() {
        let ppid_seq = vec![
            0x30, 0x1e, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x01, 0x04, 0x10, 0x88, 0x58, 0x9d,
            0xd5, 0x8b, 0xd4, 0xe8, 0x0c, 0x2b, 0x12, 0x49, 0x86, 0x22, 0xa3, 0x48, 0x77,
        ];
        let (oid, ppid) = yasna::parse_der(&ppid_seq, |reader| {
            reader.read_sequence(|reader| {
                let oid = reader.next().read_oid()?;
                let ppid = reader.next().read_bytes()?;
                Ok((oid, ppid))
            })
        })
        .unwrap();
        assert_eq!(oid, *SGX_EXTENSION_PPID);
        assert_eq!(
            ppid,
            vec![136, 88, 157, 213, 139, 212, 232, 12, 43, 18, 73, 134, 34, 163, 72, 119]
        );
    }

    #[test]
    fn sgx_extension_tcb_comp() {
        let tcb_comp_seq = vec![
            0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x02, 0x01, 0x0d,
        ];

        let (oid, tcb_comp) = yasna::parse_der(&tcb_comp_seq, |reader| {
            reader.read_sequence(|reader| {
                let oid = reader.next().read_oid()?;
                let tcb_comp = reader.next().read_u8()?;
                Ok((oid, tcb_comp))
            })
        })
        .unwrap();
        assert_eq!(oid, *SGX_EXTENSION_TCB_COMP01_SVN);
        assert_eq!(tcb_comp, 13);
    }

    #[test]
    fn sgx_extension_tcb_comp2() {
        let tcb_comp_seq = vec![
            0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x02, 0x01, 0x0d,
        ];

        let (oid, tcb_comp) = yasna::parse_der(&tcb_comp_seq, |reader| reader.read_sequence(decode_tcb_item)).unwrap();
        assert_eq!(oid, *SGX_EXTENSION_TCB_COMP01_SVN);
        assert_eq!(tcb_comp, 13);
    }

    #[test]
    fn sgx_extension_tcb() {
        let tcb_enc = vec![
            0x30, 0x82, 0x01, 0x64, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x30, 0x82, 0x01,
            0x54, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x02, 0x01, 0x0d,
            0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x02, 0x02, 0x01, 0x0d, 0x30,
            0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02, 0x30, 0x10,
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x04, 0x02, 0x01, 0x04, 0x30, 0x10, 0x06,
            0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x05, 0x02, 0x01, 0x01, 0x30, 0x11, 0x06, 0x0b,
            0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x06, 0x02, 0x02, 0x00, 0x80, 0x30, 0x10, 0x06, 0x0b,
            0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x07, 0x02, 0x01, 0x03, 0x30, 0x10, 0x06, 0x0b, 0x2a,
            0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x08, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86,
            0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x09, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48,
            0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86,
            0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
            0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0c, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
            0x01, 0x0d, 0x01, 0x02, 0x0d, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01,
            0x0d, 0x01, 0x02, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d,
            0x01, 0x02, 0x0f, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01,
            0x02, 0x10, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02,
            0x11, 0x02, 0x01, 0x09, 0x30, 0x1f, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12,
            0x04, 0x10, 0x0d, 0x0d, 0x02, 0x04, 0x01, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let (oid, tcb) = yasna::parse_der(&tcb_enc, |reader| {
            reader.read_sequence(|reader| {
                let oid = reader.next().read_oid()?;
                let tcb = reader.next().read_sequence(decode_tcb_sequence)?;
                Ok((oid, tcb))
            })
        })
        .unwrap();
        assert_eq!(oid, *SGX_EXTENSION_TCB);
        assert_eq!(
            tcb.tcb_components.0.sgxtcbcomponents.map(|c| c.svn),
            [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(tcb.cpusvn, [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(tcb.tcb_components.0.pcesvn, 9);
    }

    #[test]
    fn sgx_extension() {
        let extension = vec![
            0x30, 0x82, 0x01, 0xc1, 0x30, 0x1e, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x01, 0x04,
            0x10, 0xa9, 0xf2, 0x39, 0xa8, 0x05, 0xb7, 0xd9, 0x38, 0xf5, 0xb0, 0xea, 0x87, 0x3b, 0x69, 0xdb, 0xa7, 0x30, 0x82,
            0x01, 0x64, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x30, 0x82, 0x01, 0x54, 0x30,
            0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x01, 0x02, 0x01, 0x0d, 0x30, 0x10,
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x02, 0x02, 0x01, 0x0d, 0x30, 0x10, 0x06,
            0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02, 0x30, 0x10, 0x06, 0x0b,
            0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x04, 0x02, 0x01, 0x04, 0x30, 0x10, 0x06, 0x0b, 0x2a,
            0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x05, 0x02, 0x01, 0x01, 0x30, 0x11, 0x06, 0x0b, 0x2a, 0x86,
            0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x06, 0x02, 0x02, 0x00, 0x80, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86,
            0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x07, 0x02, 0x01, 0x03, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48,
            0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x08, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86,
            0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x09, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8,
            0x4d, 0x01, 0x0d, 0x01, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d,
            0x01, 0x0d, 0x01, 0x02, 0x0b, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01,
            0x0d, 0x01, 0x02, 0x0c, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d,
            0x01, 0x02, 0x0d, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01,
            0x02, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02,
            0x0f, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x10,
            0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11, 0x02,
            0x01, 0x09, 0x30, 0x1f, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12, 0x04, 0x10,
            0x0d, 0x0d, 0x02, 0x04, 0x01, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x10, 0x06,
            0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x03, 0x04, 0x02, 0x00, 0x00, 0x30, 0x14, 0x06, 0x0a,
            0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04, 0x04, 0x06, 0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00, 0x30,
            0x0f, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x05, 0x0a, 0x01, 0x00,
        ];
        let sgx_extension = SGXPCKCertificateExtension::parse_extension(&extension);
        assert!(sgx_extension.is_ok());
        let sgx_extension = sgx_extension.unwrap();
        assert_eq!(
            sgx_extension.ppid,
            [169, 242, 57, 168, 5, 183, 217, 56, 245, 176, 234, 135, 59, 105, 219, 167]
        );
        assert_eq!(
            sgx_extension.tcb.tcb_components.0.sgxtcbcomponents.map(|c| c.svn),
            [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(sgx_extension.tcb.tcb_components.0.pcesvn, 9);
        assert_eq!(sgx_extension.tcb.cpusvn, [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sgx_extension.pceid, 0);
        assert_eq!(sgx_extension.fmspc, Fmspc::new([0, 144, 110, 161, 0, 0]));
        assert_eq!(sgx_extension.sgx_type, SGXType::Standard);
        assert!(sgx_extension.platform_instance_id.is_none());
        assert!(sgx_extension.configuration.is_none());
    }

    #[test]
    fn sgx_extension_platform_cert() {
        let extension = Vec::<u8>::from_hex(
            "30820226301e060a2a864886f84d010d010104103f545fc38af1107f31ed41547783bcd730820163060a2a864886f84d010d0102\
             308201533010060b2a864886f84d010d0102010201033010060b2a864886f84d010d0102020201033010060b2a864886f84d010d\
             0102030201003010060b2a864886f84d010d0102040201003010060b2a864886f84d010d0102050201003010060b2a864886f84d\
             010d0102060201003010060b2a864886f84d010d0102070201003010060b2a864886f84d010d0102080201003010060b2a864886\
             f84d010d0102090201003010060b2a864886f84d010d01020a0201003010060b2a864886f84d010d01020b0201003010060b2a86\
             4886f84d010d01020c0201003010060b2a864886f84d010d01020d0201003010060b2a864886f84d010d01020e0201003010060b\
             2a864886f84d010d01020f0201003010060b2a864886f84d010d0102100201003010060b2a864886f84d010d01021102010a301f\
             060b2a864886f84d010d0102120410030300000000000000000000000000003010060a2a864886f84d010d010304020000301406\
             0a2a864886f84d010d0104040610606a000000300f060a2a864886f84d010d01050a0101301e060a2a864886f84d010d01060410\
             5e5a84633cb1ddad3d79b9bea40300923044060a2a864886f84d010d010730363010060b2a864886f84d010d0107010101ff3010\
             060b2a864886f84d010d0107020101ff3010060b2a864886f84d010d0107030101ff",
        )
        .unwrap();
        let sgx_extension = SGXPCKCertificateExtension::parse_extension(&extension);
        assert!(sgx_extension.is_ok());
        let sgx_extension = sgx_extension.unwrap();
        assert_eq!(
            sgx_extension.ppid,
            [0x3F, 0x54, 0x5F, 0xC3, 0x8A, 0xF1, 0x10, 0x7F, 0x31, 0xED, 0x41, 0x54, 0x77, 0x83, 0xBC, 0xD7]
        );
        assert_eq!(
            sgx_extension.tcb.tcb_components.0.sgxtcbcomponents.map(|c| c.svn),
            [3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(sgx_extension.tcb.tcb_components.0.pcesvn, 10);
        assert_eq!(sgx_extension.tcb.cpusvn, [3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sgx_extension.pceid, 0);
        assert_eq!(sgx_extension.fmspc, Fmspc::new([16, 96, 106, 0, 0, 0]));
        assert_eq!(sgx_extension.sgx_type, SGXType::Scalable);
        assert_eq!(
            sgx_extension.platform_instance_id.unwrap(),
            [0x5E, 0x5A, 0x84, 0x63, 0x3C, 0xB1, 0xDD, 0xAD, 0x3D, 0x79, 0xB9, 0xBE, 0xA4, 0x03, 0x00, 0x92]
        );
        let configuration = sgx_extension.configuration.unwrap();
        assert!(configuration.dynamic);
        assert!(configuration.cached_keys);
        assert!(configuration.smt_enabled);
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_pckcrt() {
        let pck = PckCert::read_from_file(
            "./tests/data/",
            "5d39f104e642e51c91507932..71b719-0f0f0205ff8007000000000000000000-0900-0000.pckcert",
        )
        .expect("validated");

        assert_eq!(get_cert_subject(&pck.ca_chain.last().unwrap()), "Intel SGX Root CA");
        assert_eq!(get_cert_subject(&pck.cert), "Intel SGX PCK Certificate");
        #[cfg(feature = "verify")]
        {
            let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
            let root_cas = [&root_ca[..]];
            let platform_crl = reqwest::blocking::get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=pem")
                .unwrap()
                .text()
                .unwrap();
            match pck.clone().verify(&root_cas, Some(&platform_crl)) {
                Err(Error::InvalidCrl(ErrMbed::HighLevel(codes::EcpVerifyFailed))) => (),
                e => panic!("Unexpected error: {:?}", e),
            }
            let processor_crl = reqwest::blocking::get("https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor&encoding=pem")
                .unwrap()
                .text()
                .unwrap();
            let pck = pck.verify(&root_cas, Some(&processor_crl)).unwrap();

            let sgx_extension = pck.sgx_extension().expect("validated");
            assert_eq!(
                sgx_extension.ppid,
                [138, 37, 248, 76, 1, 238, 38, 35, 157, 25, 11, 226, 233, 16, 18, 144]
            );
            assert_eq!(
                sgx_extension.tcb.tcb_components.0.sgxtcbcomponents.map(|c| c.svn),
                [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            );
            assert_eq!(sgx_extension.tcb.tcb_components.0.pcesvn, 9);
            assert_eq!(sgx_extension.tcb.cpusvn, [13, 13, 2, 4, 1, 128, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(sgx_extension.pceid, 0);
            assert_eq!(sgx_extension.fmspc, Fmspc::new([0, 144, 110, 161, 0, 0]));
        }
    }

    #[test]
    fn pckcrt_from_quote() {
        let quote = include_bytes!("../tests/data/quote.bin");
        let quote = Quote::parse(Cow::from(&quote[..])).unwrap();
        let sig = quote.signature::<Quote3SignatureEcdsaP256>().unwrap();
        let pck_chain: Qe3CertDataPckCertChain = sig.certification_data().unwrap();
        let pck = PckCert::from_pck_chain(pck_chain.certs.into()).unwrap();
        let sgx_extension = pck.sgx_extension().unwrap();
        assert_eq!(sgx_extension.fmspc, Fmspc::new([0, 144, 110, 161, 0, 0]));
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_pckcrts() {
        let pcks = PckCerts::read_from_file(
            "./tests/data/",
            &base16::decode("16a5b41ebb076d263a1e39e64e7175e7".as_bytes()).unwrap(),
        )
        .expect("validated");
        assert_eq!(pcks.iter().count(), 12);
        for cert in pcks.iter() {
            SGXPCKCertificateExtension::try_from(cert).expect("validated");
            assert_eq!(get_cert_subject_from_der(&cert), "Intel SGX PCK Certificate");
        }
        assert_eq!(get_cert_subject(&pcks.ca_chain.last().unwrap()), "Intel SGX Root CA");

        let cert = pcks.iter().next().expect("validated");
        let sgx_extension = SGXPCKCertificateExtension::try_from(cert).expect("validated");
        assert_eq!(
            sgx_extension.ppid,
            [138, 37, 248, 76, 1, 238, 38, 35, 157, 25, 11, 226, 233, 16, 18, 144]
        );
        assert_eq!(
            sgx_extension.tcb.tcb_components.0.sgxtcbcomponents.map(|c| c.svn),
            [14, 14, 2, 4, 1, 128, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(sgx_extension.tcb.tcb_components.0.pcesvn, 10);
        assert_eq!(sgx_extension.tcb.cpusvn, [14, 14, 2, 4, 1, 128, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(sgx_extension.pceid, 0);
        assert_eq!(sgx_extension.fmspc, Fmspc::new([0, 144, 110, 161, 0, 0]));
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_pckcrts_with_missing_certs() {
        let pcks = PckCerts::read_from_file(
            "./tests/data/",
            &base16::decode("00000000000000000000000000000000".as_bytes()).unwrap(),
        )
        .expect("validated");
        let cert = pem::pem_to_der(
            &concat!(
                "-----BEGIN CERTIFICATE-----\n",
                "MIIE8jCCBJmgAwIBAgIVAIK77m63vG5A1vcRhx5fHPY75FnQMAoGCCqGSM49BAMC\n",
                "MHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM\n",
                "EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE\n",
                "CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTIyMTIxNjEwMTk0OVoXDTI5MTIxNjEwMTk0\n",
                "OVowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE\n",
                "CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD\n",
                "VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq\n",
                "R+sFzV6WAsyc8Ka4rul7Hz7l16ToABtGYRzZd5h22Y1eljsI0Vt6GnITfHuiXyS6\n",
                "HXsyRZqE4u8nRRTsFKU3o4IDDjCCAwowHwYDVR0jBBgwFoAUlW9dzb0b4elAScnU\n",
                "9DPOAVcL3lQwawYDVR0fBGQwYjBgoF6gXIZaaHR0cHM6Ly9hcGkudHJ1c3RlZHNl\n",
                "cnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw/Y2E9\n",
                "cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBR20OYrtxnHDel8lcKFwmhx\n",
                "/UEckzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAjsGCSqGSIb4TQEN\n",
                "AQSCAiwwggIoMB4GCiqGSIb4TQENAQEEEPBi9+kxf7O+L8OZgujiZOswggFlBgoq\n",
                "hkiG+E0BDQECMIIBVTAQBgsqhkiG+E0BDQECAQIBBDAQBgsqhkiG+E0BDQECAgIB\n",
                "BDAQBgsqhkiG+E0BDQECAwIBAzAQBgsqhkiG+E0BDQECBAIBAzARBgsqhkiG+E0B\n",
                "DQECBQICAP8wEQYLKoZIhvhNAQ0BAgYCAgD/MBAGCyqGSIb4TQENAQIHAgEAMBAG\n",
                "CyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIK\n",
                "AgEAMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4\n",
                "TQENAQINAgEAMBAGCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG\n",
                "CyqGSIb4TQENAQIQAgEAMBAGCyqGSIb4TQENAQIRAgELMB8GCyqGSIb4TQENAQIS\n",
                "BBAEBAMD//8AAAAAAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQEN\n",
                "AQQEBgBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQENAQYEEIEDHYFl\n",
                "SvQX3oyiTA8B0/MwRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAG\n",
                "CyqGSIb4TQENAQcCAQH/MBAGCyqGSIb4TQENAQcDAQH/MAoGCCqGSM49BAMCA0cA\n",
                "MEQCIA6R9ZOhoLbanU/mPY1hKn3Mk4Wxo0GXb7sEtLzNYWSMAiBnbSyR4iL3qEQt\n",
                "GkDTeneBR0bJi4lCLTwIwxg6tuWjdQ==\n",
                "-----END CERTIFICATE-----\n"
            ),
            Some(PEM_CERTIFICATE),
        )
        .unwrap();
        assert_eq!(pcks.pck_data.len(), 5);
        assert_eq!(pcks.pck_data[0].cert, PckCertValue::Missing(String::from("Not available")));
        assert_eq!(pcks.pck_data[1].cert, PckCertValue::Missing(String::from("Not available")));
        assert_eq!(pcks.pck_data[2].cert, PckCertValue::Cert(cert));
        assert_eq!(pcks.iter().count(), 3);
    }

    #[test]
    fn pck_cert_value() {
        let originals = vec![
            PckCertValue::Missing(String::from("Not available")),
            PckCertValue::Missing(String::from("bla")),
            PckCertValue::Cert(vec![0, 0, 0, 0, 0, 0, 0, 0]),
        ];

        for original in originals {
            let ser = serde_json::to_string(&original).unwrap();
            let deser = serde_json::from_str(&ser).unwrap();
            assert_eq!(original, deser);
        }
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn pckcrts_conversion() {
        let pcks = PckCerts::read_from_file(
            "./tests/data/",
            &base16::decode("16a5b41ebb076d263a1e39e64e7175e7".as_bytes()).unwrap(),
        )
        .unwrap();

        for i in 0..pcks.pck_data.len() {
            let pck: PckCert<Unverified> = pcks.as_pck_certs()[i].clone();
            let cert = pem::pem_to_der(&pck.cert, Some(PEM_CERTIFICATE)).unwrap();
            assert_eq!(pcks.pck_data[i].cert, PckCertValue::Cert(cert));
            assert_eq!(pcks.ca_chain.iter().map(|c| c.trim()).collect::<Vec<&str>>(), pck.ca_chain);

            let pck: PckCerts = pck.try_into().unwrap();
            assert_eq!(
                pcks.pck_data[i].tcb.0.sgxtcbcomponents,
                pck.pck_data[0].tcb.0.sgxtcbcomponents
            );
            assert_eq!(pcks.pck_data[i].tcb.0.pcesvn, pck.pck_data[0].tcb.0.pcesvn);
            assert_eq!(pcks.pck_data[i].tcbm, pck.pck_data[0].tcbm);
            assert_eq!(pcks.pck_data[i].cert, pck.pck_data[0].cert);
        }
    }

    #[test]
    fn tcb_level_partial_cmp() {
        let base_tcb = [10, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let base = TcbComponents::<SGXSpecificTcbComponentData>::from_raw(base_tcb, 40);
        let base = &base;
        let mut other = base.clone();
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Equal));

        other = base.clone();
        other.0.sgxtcbcomponents = [10, 20, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(|c| c.into());
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Less));

        other = base.clone();
        other.0.sgxtcbcomponents = [20, 20, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(|c| c.into());
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Less));

        other = base.clone();
        other.0.sgxtcbcomponents = [0, 20, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(|c| c.into());
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Greater));

        other = base.clone();
        other.0.sgxtcbcomponents = [10, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(|c| c.into());
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Greater));

        other = base.clone();
        other.0.sgxtcbcomponents = [0, 20, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].map(|c| c.into());
        assert_eq!(base.partial_cmp(&other), None);

        other = base.clone();
        other.0.pcesvn = 50;
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Less));

        other = base.clone();
        other.0.pcesvn = 30;
        assert_eq!(base.partial_cmp(&other), Some(Ordering::Greater));
    }

    #[test]
    fn tcb_components_cpu_svn() {
        let raw_cpu_svn = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160];
        let comp = TcbComponents::<SGXSpecificTcbComponentData>::from_raw(raw_cpu_svn, 42);
        assert_eq!(comp.cpu_svn(), raw_cpu_svn);
    }

    #[test]
    #[cfg(feature = "verify")]
    fn pck_for_tcb() {
        use crate::platform;

        let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        let pck_certs = PckCerts::read_from_file(
            "./tests/data/",
            &base16::decode("881c3086c0eef78f60f5702a7e379efe".as_bytes()).unwrap())
            .unwrap();
        let tcb_info = crate::TcbInfo::<platform::SGX>::read_from_file("./tests/data/", &Fmspc::try_from("90806F000000").unwrap(), Some(19))
            .unwrap();
        // This TCB matches exactly with the first PCK cert in the list. This PCK cert must be
        // selected
        let cpusvn = [8, 8, 2, 2, 4, 1, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0];
        let pcesvn = 11;
        let pceid = 0;

        let pck_cert = pck_certs.select_pck(&tcb_info.data().unwrap(), &cpusvn, pcesvn, pceid)
            .unwrap()
            .verify(&root_cas, None)
            .unwrap();
        let ext = pck_cert.sgx_extension().unwrap();
        assert_eq!(ext.tcb.tcb_components, TcbComponents::<SGXSpecificTcbComponentData>::from_raw(cpusvn, pcesvn));
        assert_eq!(ext.tcb.cpusvn, cpusvn);
        assert_eq!(ext.pceid, pceid);
    }
}
