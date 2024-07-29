/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::convert::TryInto;
use std::marker::PhantomData;
use std::path::PathBuf;

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use sgx_isa::{Attributes, Miscselect};
#[cfg(feature = "verify")]
use {
    mbedtls::alloc::List as MbedtlsList, mbedtls::x509::certificate::Certificate, mbedtls::Error as MbedError, pkix::oid,
    pkix::pem::PEM_CERTIFICATE, pkix::x509::GenericCertificate, pkix::FromBer, std::ops::Deref,
};

use crate::io::{self};
use crate::{Error, TcbStatus, Unverified, VerificationType, Verified};

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Tcb {
    isvsvn: u16,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    tcb: Tcb,
    tcb_date: String,
    tcb_status: TcbStatus,
    #[serde(default, rename = "advisoryIDs", skip_serializing_if = "Vec::is_empty")]
    advisory_ids: Vec<String>,
}

impl TcbLevel {
    pub fn tcb_status(&self) -> &TcbStatus {
        &self.tcb_status
    }
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity<V: VerificationType = Verified> {
    version: u16,
    id: String,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u32,
    #[serde(deserialize_with = "miscselect_deserializer", serialize_with = "miscselect_serializer")]
    miscselect: Miscselect,
    #[serde(
        deserialize_with = "miscselect_mask_deserializer",
        serialize_with = "miscselect_mask_serializer"
    )]
    miscselect_mask: u32,
    #[serde(deserialize_with = "attributes_deserializer", serialize_with = "attributes_serializer")]
    attributes: Attributes,
    #[serde(deserialize_with = "attributes_deserializer", serialize_with = "attributes_serializer")]
    attributes_mask: Attributes,
    #[serde(deserialize_with = "mrsigner_deserializer", serialize_with = "mrsigner_serializer")]
    mrsigner: [u8; 32],
    isvprodid: u16,
    tcb_levels: Vec<TcbLevel>,
    #[serde(skip)]
    type_: PhantomData<V>,
}

impl<'de> Deserialize<'de> for QeIdentity<Unverified> {
    fn deserialize<D>(deserializer: D) -> Result<QeIdentity<Unverified>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Dummy {
            version: u16,
            id: String,
            issue_date: String,
            next_update: String,
            tcb_evaluation_data_number: u32,
            #[serde(deserialize_with = "miscselect_deserializer", serialize_with = "miscselect_serializer")]
            miscselect: Miscselect,
            #[serde(
                deserialize_with = "miscselect_mask_deserializer",
                serialize_with = "miscselect_mask_serializer"
            )]
            miscselect_mask: u32,
            #[serde(deserialize_with = "attributes_deserializer", serialize_with = "attributes_serializer")]
            attributes: Attributes,
            #[serde(deserialize_with = "attributes_deserializer", serialize_with = "attributes_serializer")]
            attributes_mask: Attributes,
            #[serde(deserialize_with = "mrsigner_deserializer", serialize_with = "mrsigner_serializer")]
            mrsigner: [u8; 32],
            isvprodid: u16,
            tcb_levels: Vec<TcbLevel>,
        }

        let Dummy {
            version,
            id,
            issue_date,
            next_update,
            tcb_evaluation_data_number,
            miscselect,
            miscselect_mask,
            attributes,
            attributes_mask,
            mrsigner,
            isvprodid,
            tcb_levels,
        } = Dummy::deserialize(deserializer)?;

        Ok(QeIdentity::<Unverified> {
            version,
            id,
            issue_date,
            next_update,
            tcb_evaluation_data_number,
            miscselect,
            miscselect_mask,
            attributes,
            attributes_mask,
            mrsigner,
            isvprodid,
            tcb_levels,
            type_: PhantomData,
        })
    }
}

impl QeIdentity {
    /// Returns the most recent TCB level matching the isvsvn
    pub fn find_tcb_level<'a>(&'a self, isvsvn: u16) -> Option<&'a TcbLevel> {
        // Note: tcb levels are ordered in descending order
        for tcb in self.tcb_levels.iter() {
            if tcb.tcb.isvsvn <= isvsvn {
                return Some(tcb);
            }
        }
        None
    }

    pub fn mrsigner(&self) -> &[u8; 32] {
        &self.mrsigner
    }

    pub fn isvprodid(&self) -> u16 {
        self.isvprodid
    }

    pub fn attributes<'a>(&'a self) -> &'a Attributes {
        &self.attributes
    }

    pub fn attributes_mask<'a>(&'a self) -> &'a Attributes {
        &self.attributes_mask
    }

    pub fn miscselect<'a>(&'a self) -> &'a Miscselect {
        &self.miscselect
    }

    pub fn miscselect_mask(&self) -> Miscselect {
        Miscselect::from_bits_truncate(self.miscselect_mask)
    }
}

fn mrsigner_deserializer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    let mrsigner = String::deserialize(deserializer)?;
    let mrsigner = base16::decode(&mrsigner).map_err(de::Error::custom)?;
    mrsigner.as_slice().try_into().map_err(de::Error::custom)
}

fn mrsigner_serializer<S>(mrsigner: &[u8; 32], serializer: S) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ::serde::Serializer,
{
    let mrsigner = base16::encode_upper(mrsigner);
    serializer.serialize_str(&mrsigner)
}

fn attributes_deserializer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Attributes, D::Error> {
    let attributes = String::deserialize(deserializer)?;
    let attributes = base16::decode(&attributes).map_err(de::Error::custom)?;
    Attributes::try_copy_from(&attributes).ok_or_else(|| de::Error::custom("Could not parse attribtes"))
}

fn attributes_serializer<S>(attributes: &Attributes, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ::serde::Serializer,
{
    let attributes: &[u8] = attributes.as_ref();
    let attributes = base16::encode_upper(&attributes);
    serializer.serialize_str(&attributes)
}

fn miscselect_deserializer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Miscselect, D::Error> {
    let miscselect = String::deserialize(deserializer)?;
    let miscselect = u32::from_str_radix(&miscselect, 16).map_err(de::Error::custom)?;
    Miscselect::from_bits(miscselect).ok_or_else(|| de::Error::custom("Could not parse miscselect"))
}

fn miscselect_serializer<S>(miscselect: &Miscselect, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ::serde::Serializer,
{
    let miscselect = miscselect.bits();
    let miscselect = base16::encode_upper(&miscselect.to_be_bytes());
    serializer.serialize_str(&miscselect)
}

fn miscselect_mask_deserializer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let miscselect = String::deserialize(deserializer)?;
    u32::from_str_radix(&miscselect, 16).map_err(de::Error::custom)
}

fn miscselect_mask_serializer<S>(miscselect: &u32, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ::serde::Serializer,
{
    let miscselect = base16::encode_upper(&miscselect.to_be_bytes());
    serializer.serialize_str(&miscselect)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QeIdentitySigned {
    raw_enclave_identity: String,
    signature: Vec<u8>,
    ca_chain: Vec<String>,
}

impl QeIdentitySigned {
    const DEFAULT_FILENAME: &'static str = "qe3_identity.id";

    pub fn parse(body: &String, ca_chain: Vec<String>) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct IntelQeIdentitySigned<'a> {
            #[serde(borrow)]
            enclave_identity: &'a RawValue,
            #[serde(deserialize_with = "crate::intel_signature_deserializer")]
            signature: Vec<u8>,
        }
        let IntelQeIdentitySigned {
            enclave_identity,
            signature,
        } = serde_json::from_str(&body)?;
        Ok(QeIdentitySigned::new(enclave_identity.to_string(), signature, ca_chain))
    }

    pub fn new(raw_enclave_identity: String, signature: Vec<u8>, ca_chain: Vec<String>) -> Self {
        QeIdentitySigned {
            raw_enclave_identity,
            signature,
            ca_chain,
        }
    }

    pub fn write_to_file(&self, output_dir: &str) -> Result<String, Error> {
        io::write_to_file(&self, output_dir, Self::DEFAULT_FILENAME)?;
        Ok(Self::DEFAULT_FILENAME.to_string())
    }

    pub fn write_to_file_if_not_exist(&self, output_dir: &str) -> Result<Option<PathBuf>, Error> {
        io::write_to_file_if_not_exist(&self, output_dir, &Self::DEFAULT_FILENAME)
    }

    pub fn read_from_file(input_dir: &str) -> Result<Self, Error> {
        let identity: Self = io::read_from_file(input_dir, Self::DEFAULT_FILENAME)?;
        Ok(identity)
    }

    pub fn raw_qe_identity(&self) -> &String {
        &self.raw_enclave_identity
    }

    pub fn signature(&self) -> &Vec<u8> {
        &self.signature
    }

    pub fn certificate_chain(&self) -> &Vec<String> {
        &self.ca_chain
    }

    #[cfg(feature = "verify")]
    pub fn verify<B: Deref<Target = [u8]>>(&self, trusted_root_certs: &[B]) -> Result<QeIdentity, Error> {
        // check cert chain
        let (chain, root) = crate::create_cert_chain(&self.ca_chain)?;
        let mut leaf = chain.first().unwrap_or(&root).clone();
        let root_list = std::iter::once(root).collect();
        if 0 < chain.len() {
            let trust_ca: MbedtlsList<Certificate> = chain.into_iter().collect();
            Certificate::verify(&trust_ca, &root_list, None, None).map_err(|e| Error::InvalidQe3Id(e))?;
        }

        // Check signature on data
        let mut hash = [0u8; 32];
        mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, self.raw_enclave_identity.as_bytes(), &mut hash).unwrap();
        leaf.public_key_mut()
            .verify(mbedtls::hash::Type::Sha256, &hash, &self.signature)
            .map_err(|e| Error::InvalidQe3Id(e))?;

        // Check common name TCB cert
        let leaf = self.ca_chain.first().ok_or(Error::IncorrectCA)?;
        let tcb =
            &pkix::pem::pem_to_der(&leaf, Some(PEM_CERTIFICATE)).ok_or(Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        let tcb = GenericCertificate::from_ber(&tcb).map_err(|_| Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        let name = tcb
            .tbscert
            .subject
            .get(&*oid::commonName)
            .ok_or(Error::InvalidQe3Id(MbedError::X509BadInputData))?;
        if String::from_utf8_lossy(&name.value()) != "Intel SGX TCB Signing" {
            return Err(Error::IncorrectCA);
        }

        crate::check_root_ca(trusted_root_certs, &root_list)?;

        let QeIdentity::<Unverified> {
            version,
            id,
            issue_date,
            next_update,
            tcb_evaluation_data_number,
            miscselect,
            miscselect_mask,
            attributes,
            attributes_mask,
            mrsigner,
            isvprodid,
            tcb_levels,
            type_: PhantomData,
        } = serde_json::from_str(&self.raw_enclave_identity).map_err(|e| Error::ParseError(e))?;
        if version != 2 {
            return Err(Error::UnknownQeIdentityVersion(version));
        }
        Ok(QeIdentity::<Verified> {
            version,
            id,
            issue_date,
            next_update,
            tcb_evaluation_data_number,
            miscselect,
            miscselect_mask,
            attributes,
            attributes_mask,
            mrsigner,
            isvprodid,
            tcb_levels,
            type_: PhantomData,
        })
    }
}

#[cfg(feature = "verify")]
#[cfg(test)]
mod tests {
    #[cfg(not(target_env = "sgx"))]
    use crate::qe_identity::QeIdentitySigned;

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_qe3_identity() {
        let qe_id = QeIdentitySigned::read_from_file("./tests/data/").expect("validated");

        let root_cert = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certs = [&root_cert[..]];
        assert!(qe_id.verify(&root_certs).is_ok());
    }

    #[test]
    #[cfg(not(target_env = "sgx"))]
    fn read_corrupted_qe3_identity() {
        let qeid = QeIdentitySigned::read_from_file("./tests/data/corrupted/").unwrap();

        let root_cert = include_bytes!("../tests/data/root_SGX_CA_der.cert");
        let root_certs = [&root_cert[..]];
        assert!(qeid.verify(&root_certs).is_err());
    }
}
