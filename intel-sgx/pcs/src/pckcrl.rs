/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::path::PathBuf;

use pkix::pem::PEM_CRL;
use serde::{Deserialize, Deserializer, Serialize};
use std::marker::PhantomData;
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::{List as MbedtlsList},
    mbedtls::x509::{Certificate, Crl},
    std::ffi::CString,
    std::ops::Deref,
};

use crate::io::{self};
use crate::{Error, Unverified, VerificationType, Verified};

#[derive(Debug, PartialEq, Eq)]
pub enum PckCrlCa {
    Platform,
    Processor,
}

#[derive(Clone, Serialize, Debug, Eq, PartialEq)]
pub struct PckCrl<V: VerificationType = Verified> {
    crl: String,
    ca_chain: Vec<String>,
    #[serde(skip)]
    type_: PhantomData<V>,
}

impl<'de> Deserialize<'de> for PckCrl<Unverified> {
    fn deserialize<D>(deserializer: D) -> Result<PckCrl<Unverified>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Dummy {
            crl: String,
            ca_chain: Vec<String>,
        }

        let Dummy { crl, ca_chain } = Dummy::deserialize(deserializer)?;
        Ok(PckCrl::<Unverified> {
            crl,
            ca_chain,
            type_: PhantomData,
        })
    }
}

impl PckCrl<Unverified> {
    pub fn new(crl: String, ca_chain: Vec<String>) -> Result<PckCrl<Unverified>, Error> {
        let crl = PckCrl { crl, ca_chain, type_: PhantomData };

        Ok(crl)
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(self, trusted_root_certs: &[B]) -> Result<PckCrl<Verified>, Error> {
        // Check if ca_chain is a valid chain
        let (chain, root) = crate::create_cert_chain(&self.ca_chain)?;
        let chain: MbedtlsList<Certificate> = chain.into_iter().collect();
        let root = std::iter::once(root).collect();
        let mut err = String::default();
        Certificate::verify(&chain, &root, None, Some(&mut err))
            .map_err(|e| Error::InvalidCrl(e))?;

        // Check if the root in self.ca_chain is in `trusted_root_certs`
        crate::check_root_ca(trusted_root_certs, &root)?;

        // Check if first entry in CA list signed CRL
        let crl = self.as_mbedtls_crl()?;
        let crl_signature = crl.signature()
            .map_err(|e| Error::InvalidCrl(e))?;
        let crl_tbs = crl.tbs_raw()
            .map_err(|e| Error::InvalidCrl(e))?;
        let mut hash = [0u8; 32];
        mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, &crl_tbs, &mut hash).unwrap();

        let pck_ca = self.ca_chain.first()
            .ok_or(Error::InvalidPck("Pck CRL doesn't have a CA".into()))?;
        let pck_ca = CString::new(pck_ca.as_bytes()).map_err(|_| Error::InvalidCaFormat)?;
        let mut pck_ca = Certificate::from_pem(pck_ca.as_bytes_with_nul()).map_err(|_| Error::InvalidCaFormat)?;
        let pck_ca = pck_ca.public_key_mut();
        pck_ca
            .verify(mbedtls::hash::Type::Sha256, &hash, &crl_signature)
            .map_err(|e| Error::InvalidCrl(e))?;

        // Sanity check on Pck CRL
        self.ca().ok_or(Error::InvalidCrlFormat)?;

        let PckCrl { crl, ca_chain, .. } = self;
        Ok(PckCrl::<Verified>{ crl, ca_chain, type_: PhantomData})
    }

    pub fn read_from_file(input_dir: &str, ca: PckCrlCa) -> Result<Self, Error> {
        let filename = Self::filename_from_ca(Some(ca));
        let crl: Self = io::read_from_file(input_dir, &filename)?;
        Ok(crl)
    }
}

impl<V: VerificationType> PckCrl<V> {
    const DEFAULT_FILENAME: &'static str = "processor.crl";

    fn filename_from_ca(ca: Option<PckCrlCa>) -> String {
        if let Some(PckCrlCa::Platform) = ca {
            String::from("platform.crl")
        } else {
            Self::DEFAULT_FILENAME.to_string()
        }
    }

    pub fn filename(&self) -> String {
        Self::filename_from_ca(self.ca())
    }

    pub fn write_to_file(&self, output_dir: &str) -> Result<String, Error> {
        let filename = self.filename();
        io::write_to_file(&self, output_dir, &filename)?;
        Ok(filename)
    }

    pub fn write_to_file_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        let filename = self.filename();
        io::write_to_file_if_not_exist(&self, output_dir, &filename)
    }

    pub fn crl_as_pem(&self) -> &String {
        &self.crl
    }

    pub fn crl_as_der(&self) -> Result<Vec<u8>, Error> {
        pkix::pem::pem_to_der(&self.crl, Some(PEM_CRL)).ok_or(Error::InvalidCrlFormat)
    }

    pub fn certificate_chain(&self) -> &Vec<String> {
        &self.ca_chain
    }

    #[cfg(feature = "verify")]
    pub(crate) fn as_mbedtls_crl(&self) -> Result<Crl, Error> {
        let c = CString::new(self.crl.as_bytes()).map_err(|_| Error::InvalidCrlFormat)?;
        let mut crl = Crl::new();
        crl.push_from_pem(c.as_bytes_with_nul()).map_err(|_| Error::InvalidCrlFormat)?;
        Ok(crl)
    }

    #[cfg(feature = "verify")]
    fn ca(&self) -> Option<PckCrlCa> {
        let issuer = self
            .as_mbedtls_crl()
            .ok()
            .and_then(|crl| crl.issuer().ok())?;
        if issuer.contains("Intel SGX PCK Platform CA") {
            Some(PckCrlCa::Platform)
        } else {
            if issuer.contains("Intel SGX PCK Processor CA") {
                Some(PckCrlCa::Processor)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_env = "sgx"))]
    use crate::pckcrl::{PckCrl, PckCrlCa};

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn read_pck_crl() {
        let crl = PckCrl::read_from_file("./tests/data/", PckCrlCa::Processor).unwrap();
        assert_eq!(crl.ca(), Some(PckCrlCa::Processor));
        let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        crl.verify(&root_cas).unwrap();
    }

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn read_platform_pck_crl() {
        let pckcrl = PckCrl::read_from_file("./tests/data/", PckCrlCa::Platform).unwrap();
        let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        pckcrl.clone().verify(&root_cas).unwrap();
        assert_eq!(pckcrl.ca(), Some(PckCrlCa::Platform));
    }
}
