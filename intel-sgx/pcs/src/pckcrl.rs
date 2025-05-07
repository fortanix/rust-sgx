/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::path::PathBuf;

use pkix::pem::PEM_CRL;
use serde::{Deserialize, Serialize};
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::{List as MbedtlsList},
    mbedtls::x509::{Certificate, Crl},
    std::ffi::CString,
    std::ops::Deref,
};

use crate::io::{self};
use crate::Error;

enum PckCrlCa {
    Platform,
    Processor,
}

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PckCrl {
    crl: String,
    ca_chain: Vec<String>,
}

impl PckCrl {
    const DEFAULT_FILENAME: &'static str = "processor.crl";

    pub fn new(crl: String, ca_chain: Vec<String>) -> Result<PckCrl, Error> {
        let crl = PckCrl { crl, ca_chain };

        Ok(crl)
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(self, trusted_root_certs: &[B]) -> Result<(), Error> {
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
            .map_err(|_| Error::InvalidTcbInfo("Signature verification failed".into()))?;

        // Sanity check on Pck CRL
        if Self::ca(&crl).is_none() {
            return Err(Error::InvalidCrlFormat);
        }

        Ok(())
    }

    pub fn filename() -> String {
        Self::DEFAULT_FILENAME.to_string()
    }

    pub fn write_to_file(&self, output_dir: &str) -> Result<String, Error> {
        io::write_to_file(&self, output_dir, Self::DEFAULT_FILENAME)?;
        Ok(Self::DEFAULT_FILENAME.to_string())
    }

    pub fn write_to_file_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        io::write_to_file_if_not_exist(&self, output_dir, &Self::DEFAULT_FILENAME)
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let crl: Self = io::read_from_file(input_dir, Self::DEFAULT_FILENAME)?;
        Ok(crl)
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
    fn as_mbedtls_crl(&self) -> Result<Crl, Error> {
        let c = CString::new(self.crl.as_bytes()).map_err(|_| Error::InvalidCrlFormat)?;
        let mut crl = Crl::new();
        crl.push_from_pem(c.as_bytes_with_nul()).map_err(|_| Error::InvalidCrlFormat)?;
        Ok(crl)
    }

    #[cfg(feature = "verify")]
    fn ca(crl: &Crl) -> Option<PckCrlCa> {
        let issuer = crl.issuer().ok()?;
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

    #[cfg(feature = "verify")]
    pub fn revoked_serials(&self) -> Result<Vec<Vec<u8>>, Error> {
        let crl = self.as_mbedtls_crl()?;
        Ok(crl.revoked_serials())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_env = "sgx"))]
    use crate::pckcrl::PckCrl;

    #[cfg(not(target_env = "sgx"))]
    #[test]
    fn read_pck_crl() {
        assert!(PckCrl::read_from_file("./tests/data/").is_ok());
    }

    #[cfg(all(not(target_env = "sgx"), feature = "verify"))]
    #[test]
    fn read_platform_pck_crl() {
        let pckcrl = PckCrl::read_from_file("./tests/data/platform/").unwrap();
        let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];
        pckcrl.clone().verify(&root_cas).unwrap();
        assert_eq!(pckcrl.revoked_serials().unwrap().len(), 44);
    }
}
