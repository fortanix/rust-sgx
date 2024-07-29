/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::path::PathBuf;

use pkix::pem::PEM_CRL;
use serde::{Deserialize, Serialize};

use crate::io::{self};
use crate::Error;

#[derive(Clone, Serialize, Deserialize, Debug)]
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
