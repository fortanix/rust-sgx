/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
use std::fmt;
use std::convert::TryInto;

use aesm_client::AesmClient;
use dcap_ql::quote::{Qe3CertDataPpid, Quote, Quote3SignatureEcdsaP256, QuoteHeader};
use sgx_isa::Targetinfo;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as IsgxDevice;
#[cfg(unix)]
use sgxs_loaders::isgx::Device as IsgxDevice;

fn get_algorithm_id(key_id: &Vec<u8>) -> u32 {
    const ALGORITHM_OFFSET: usize = 154;

    let mut bytes: [u8; 4] = Default::default();
    bytes.copy_from_slice(&key_id[ALGORITHM_OFFSET..ALGORITHM_OFFSET + 4]);
    u32::from_le_bytes(bytes)
}

struct PrintHex<'a>(&'a [u8]);

impl<'a> fmt::Display for PrintHex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

pub struct PckCertId {
    pub cd_ppid: Qe3CertDataPpid<'static>,
    pub qe_id: [u8; 16],
}

impl ToString for PckCertId {
    fn to_string(&self) -> String {
        format!(
            "{ppid},{pceid},{cpusvn},{pcesvn},{qe3id}",
            ppid = PrintHex(&self.cd_ppid.ppid),
            pceid = PrintHex(&self.cd_ppid.pceid.to_le_bytes()),
            cpusvn = PrintHex(&self.cd_ppid.cpusvn),
            pcesvn = PrintHex(&self.cd_ppid.pcesvn.to_le_bytes()),
            qe3id = PrintHex(&self.qe_id),
        )
    }
}

pub fn retrieve_pckid_str() -> Result<PckCertId, &'static str> {
    const SGX_QL_ALG_ECDSA_P256: u32 = 2;

    let mut device = IsgxDevice::new()
        .map_err(|_| "Error opening SGX device")?
        .einittoken_provider(AesmClient::new())
        .build();

    let client = AesmClient::new();

    let key_ids = client
        .get_supported_att_key_ids()
        .map_err(|_| "AESM communication error getting attestation key ID")?;

    let ecdsa_key_id = key_ids
        .into_iter()
        .find(|id| SGX_QL_ALG_ECDSA_P256 == get_algorithm_id(id))
        .ok_or("No appropriate attestation key ID")?;

    let quote_info = client
        .init_quote_ex(ecdsa_key_id.clone())
        .map_err(|_| "Error during quote initialization")?;

    let ti = Targetinfo::try_copy_from(quote_info.target_info()).unwrap();
    let report = report_test::report(&ti, &mut device).unwrap();

    let res = client
        .get_quote_ex(ecdsa_key_id, report.as_ref().to_owned(), None, vec![0; 16])
        .map_err(|_| "Error obtaining quote")?;

    let quote = Quote::parse(res.quote()).map_err(|_| "Error parsing quote")?;
    let QuoteHeader::V3 { user_data, .. } = quote.header();
    let sig = quote
        .signature::<Quote3SignatureEcdsaP256>()
        .map_err(|_| "Error parsing requested signature type")?;
    let cd_ppid = sig
        .certification_data::<Qe3CertDataPpid>()
        .map_err(|_| "Certification data is already available for the current platform")?;

    Ok(PckCertId {
        cd_ppid: cd_ppid.clone_owned(),
        qe_id: user_data[0..16].try_into().unwrap(),
    })
}
