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
    mbedtls::x509::Crl,
    std::ffi::CString,
};

use crate::io::{self};
use crate::Error;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PckCrl {
    crl: String,
    ca_chain: Vec<String>,
}

impl PckCrl {
    const DEFAULT_FILENAME: &'static str = "processor.crl";

    pub fn new(crl: String, ca_chain: Vec<String>) -> Result<PckCrl, Error> {
        let crl = PckCrl { crl, ca_chain };
        //TODO: verify ca_chain
        // https://fortanix.atlassian.net/browse/PROD-2046
        Ok(crl)
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
}
