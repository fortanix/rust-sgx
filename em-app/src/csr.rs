/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use mbedtls::hash;
use mbedtls::pk::{Pk, Type as PkType};
use pkix::{DerWrite};
use pkix::bit_vec::BitVec;
use pkix::pem::{der_to_pem, PEM_CERTIFICATE_REQUEST};
use pkix::pkcs10::{CertificationRequest, CertificationRequestInfo};
use pkix::types::{Attribute, Extension, ObjectIdentifier, TaggedDerValue, RsaPkcs15, EcdsaPkcs15, Sha256, DerSequence, Name};
use yasna::tags::TAG_UTF8STRING;
use pkix;

use crate::Error;

pub use mbedtls::rng::Rdrand as FtxRng;
use crate::Result;

#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    EcdsaPkcs15,
    RsaPkcs15,
}

/// Operations needed on any input key pair. This is already implemented for mbedtls::Pk.
pub trait ExternalKey {
    fn get_public_key_der(&mut self) -> Result<Vec<u8>>;
    fn sign_sha256(&mut self, input: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm)>;
}

pub trait CsrSigner {
    fn get_public_key_der(&mut self) -> Result<Vec<u8>>;
    fn sign_csr(&mut self, csr: &CertificationRequestInfo<DerSequence>) -> Result<String>;
}

impl<T> CsrSigner for T
where
    T: ExternalKey
{
    fn get_public_key_der(&mut self) -> Result<Vec<u8>> {
        ExternalKey::get_public_key_der(self)
    }

    fn sign_csr(&mut self, csr: &CertificationRequestInfo<DerSequence>) -> Result<String>
    {
        let reqinfo = DerSequence::from(pkix::yasna::construct_der(|writer| {
            csr.write(writer)
        }));

        let (sig, sigalg) = self.sign_sha256(reqinfo.as_ref())?;

        let csr = match sigalg {
            SignatureAlgorithm::EcdsaPkcs15 => pkix::yasna::construct_der(|writer| {
                CertificationRequest {
                    reqinfo,
                    sigalg: EcdsaPkcs15(Sha256),
                    sig: BitVec::from_bytes(&sig),
                }.write(writer)
            }),
            SignatureAlgorithm::RsaPkcs15 => pkix::yasna::construct_der(|writer| {
                CertificationRequest {
                    reqinfo,
                    sigalg: RsaPkcs15(Sha256),
                    sig: BitVec::from_bytes(&sig),
                }.write(writer)
            })
        };
        
        Ok(der_to_pem(&csr, PEM_CERTIFICATE_REQUEST))
    }
}

impl ExternalKey for Pk {
    fn get_public_key_der(&mut self) -> Result<Vec<u8>> {
        Ok(self.write_public_der_vec().map_err(|e| Error::ExternalKey(Box::new(e)))?)
    }
    
    fn sign_sha256(&mut self, input: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm)> {
        let mut hash = [0u8; 32];
        hash::Md::hash(hash::Type::Sha256, &input, &mut hash).map_err(|e| Error::ExternalKey(Box::new(e)))?;
        
        let mut sig = vec![0u8; (self.len()+7)/8];
        self.sign(hash::Type::Sha256, &hash, &mut sig, &mut FtxRng).map_err(|e| Error::ExternalKey(Box::new(e)))?;

        let sigalg = match self.pk_type() {
            PkType::Rsa | PkType::RsaAlt | PkType::RsassaPss => Ok(SignatureAlgorithm::RsaPkcs15),
            PkType::Eckey | PkType::Ecdsa => Ok(SignatureAlgorithm::EcdsaPkcs15),
            _ => Err(Error::ExternalKeyString(format!("Invalid key type: {:?}", self.pk_type()))),
        }?;
        
        Ok((sig, sigalg))
    }
}

pub fn get_csr_common_name(signer: &mut dyn CsrSigner,
                           common_name: &str,
                           attributes: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>,
                           extensions: &Option<Vec<(ObjectIdentifier, bool, Vec<u8>)>>
) -> Result<String> {
    let subject = vec![(pkix::oid::commonName.clone(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, common_name.as_bytes().to_vec()))].into();
    get_csr(signer, &subject, attributes, extensions)
}

pub fn get_csr(signer: &mut dyn CsrSigner,
               subject: &Name,
               attributes: Vec<(ObjectIdentifier, Vec<Vec<u8>>)>,
               extensions: &Option<Vec<(ObjectIdentifier, bool, Vec<u8>)>>
) -> Result<String> {

    let pub_key_der = signer.get_public_key_der()?;

    let mut attributes = attributes.iter().map(|&(ref oid,ref elems)| {
        Attribute {
            oid: oid.clone(),
            value: elems.iter().map(|e| e[..].into()).collect(),
        }
    }).collect::<Vec<_>>();

    let extension_bytes = extensions.as_ref().and_then(|ext| {
        Some(pkix::yasna::construct_der(|w|w.write_sequence(|w|{
            for &(ref oid, critical, ref value) in ext {
                Extension {
                    oid: oid.clone(),
                    critical: critical,
                    value: value[..].to_owned(),
                }.write(w.next())
            }
        })))
    });
    
    if let Some(bytes) = &extension_bytes {
        attributes.push(Attribute{
            oid: pkix::oid::extensionRequest.clone(),
            value: vec![bytes[..].into()],
        });
    }
    
    let csr = CertificationRequestInfo {
        subject: subject.to_owned(),
        spki: DerSequence::from(&pub_key_der[..]),
        attributes: attributes,
    };
    
    signer.sign_csr(&csr)
}

