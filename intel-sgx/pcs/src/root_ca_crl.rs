/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
use crate::{io, Error};
use crate::{DcapArtifactIssuer, Unverified, VerificationType, Verified};
use serde::{Deserialize, Serialize};

#[cfg(feature = "verify")]
use {mbedtls::x509::Certificate, std::ops::Deref};

/// Type that represents the Root CA CRL within the Intel PCS infrastructures.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RootCaCrl<V: VerificationType = Verified> {
    /// The CRL itself in PEM format
    crl: String,
    #[serde(skip_serializing)]
    _type: V,
}

impl RootCaCrl<Unverified> {
    pub fn new(crl: String) -> Result<Self, Error> {
        let crl = Self {
            crl,
            _type: Unverified,
        };
        Ok(crl)
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(
        self,
        trusted_root_certs: &[B],
    ) -> Result<RootCaCrl<Verified>, Error> {
        let crl = crate::as_mbedtls_crl(&self.crl)?;
        let crl_signature = crl.signature().map_err(|e| Error::InvalidCrl(e))?;
        let crl_tbs = crl.tbs_raw().map_err(|e| Error::InvalidCrl(e))?;
        let mut hash = [0u8; 32];
        mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, &crl_tbs, &mut hash).unwrap();

        // Since we have no way to find the correct CA using its key identifier/serial,
        // then we just iterate the root certificates manually. If any of it gives OK
        // verification, then it is the correct CRL
        let root_ca_found = trusted_root_certs.iter().find_map(|cert_der| {
            Certificate::from_der(cert_der).map(|mut cert| {
                let verify = cert.public_key_mut()
                    .verify(mbedtls::hash::Type::Sha256, &hash, &crl_signature)
                    .is_ok();

                if verify {
                    Some(cert)
                } else {
                    None
                }
            }).unwrap_or(None)
        });

        if let Some(_) = root_ca_found {
            let RootCaCrl { crl, .. } = self;
            Ok(RootCaCrl::<Verified> {
                crl,
                _type: Verified,
            })
        } else {
            Err(Error::IncorrectCA)
        }
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let filename = crate::PckCrl::<Unverified>::filename_from_ca(DcapArtifactIssuer::SGXRootCA);
        let crl: Self = io::read_from_file(input_dir, &filename)?;
        Ok(crl)
    }
}

impl RootCaCrl<Verified> {
    pub fn crl(&self) -> &String {
        &self.crl
    }
}

#[cfg(test)]
#[cfg(feature = "verify")]
mod tests {
    use super::RootCaCrl;

    #[test]
    fn root_ca_crl_parse() {
        let root_ca = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_cas = [&root_ca[..]];

        let crl_pem = include_str!("../tests/data/IntelSGXRootCA.crl");
        let root_ca_crl = RootCaCrl::new(crl_pem.to_string()).unwrap();

        let _ = root_ca_crl.verify(&root_cas).unwrap();
    }

}
