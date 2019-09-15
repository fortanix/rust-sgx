/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use std::borrow::Cow;
use std::collections::hash_map::{Entry, HashMap};
use std::os::raw::c_char;
use std::sync::Mutex;
use std::{mem, ptr, slice};

use byteorder::{ByteOrder, LE};
use rustc_serialize::hex::{FromHex, ToHex};

use dcap_ql::Quote3Error;

mod ql;

use crate::ql::*;

fn u16_le(v: u16) -> [u8; 2] {
    let mut ret = [0u8; 2];
    LE::write_u16(&mut ret, v);
    ret
}

#[no_mangle]
pub extern "C" fn sgx_ql_write_persistent_data(
    _buf: *const u8,
    _len: u32,
    _label: *const c_char,
) -> Quote3Error {
    Quote3Error::PlatformLibUnavailable
}

#[no_mangle]
pub extern "C" fn sgx_ql_read_persistent_data(
    _buf: *mut u8,
    _len: *mut u32,
    _label: *const c_char,
) -> Quote3Error {
    Quote3Error::PlatformLibUnavailable
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct PckCertInfo<'a> {
    certchain: Cow<'a, [u8]>,
    tcbm_cpusvn: Cow<'a, [u8]>,
    tcbm_pcesvn: u16,
}

/// Get a quote with the “raw TCB”, meaning `PPID_RSA3072_ENCRYPTED`.
///
/// Results may be cached.
// Use the Quoting Library (recursively) to try to get a quote with the “raw
// TCB”, meaning `PPID_RSA3072_ENCRYPTED`. Hopefully, the QL will call
// `sgx_ql_get_quote_config` again in the same instance of this module, except
// now `get_certdata` will return early with an error because it is
// re-entered. This error should cause the QL to generate a
// `PPID_RSA3072_ENCRYPTED` quote.
//
// It doesn't matter which enclave the quote is for, so we just use a
// purpose-built built-in enclave to get a report.
fn get_quote_with_raw_tcb() -> Result<Vec<u8>, Quote3Error> {
    let ti = dcap_ql::target_info().map_err(|e| {
        error!("PPID query: failed to obtain target info: {:?}", e);
        Quote3Error::NoPlatformCertData
    })?;
    let mut loader = dcap_ql::enclave_loader().map_err(|e| {
        error!("PPID query: failed to load enclave loader: {}", e);
        Quote3Error::NoPlatformCertData
    })?;
    let report = report_test::report(&ti, &mut loader).map_err(|e| {
        error!("PPID query: {}", e);
        Quote3Error::NoPlatformCertData
    })?;
    let quote = dcap_ql::quote(&report).map_err(|e| {
        error!("PPID query: failed to obtain quote: {:?}", e);
        Quote3Error::NoPlatformCertData
    })?;
    Ok(quote)
}

/// Check if a quote matches the QE ID and parse the QE certification data from
/// the quote.
fn parse_certdata(
    qe_id: sgx_quote::QeId,
    quote: &[u8],
) -> Result<sgx_quote::Qe3CertDataPpid<'static>, Quote3Error> {
    let quote = sgx_quote::Quote::parse(quote).map_err(|e| {
        error!("PPID query: failed to parse quote: {}", e);
        Quote3Error::NoPlatformCertData
    })?;

    let sgx_quote::QuoteHeader::V3 {
        qe3_vendor_id,
        user_data,
        ..
    } = quote.header();

    if **qe3_vendor_id != sgx_quote::QE3_VENDOR_ID_INTEL {
        error!("PPID query: QE vendor ID is not Intel");
        return Err(Quote3Error::NoPlatformCertData);
    }

    let mut qe_id = qe_id.into_owned();
    qe_id.resize(20usize, 0u8);
    if *qe_id != **user_data {
        error!("PPID query: QE ID mismatch");
        return Err(Quote3Error::NoPlatformCertData);
    }

    let sig = quote
        .signature::<sgx_quote::Quote3SignatureEcdsaP256>()
        .map_err(|e| {
            error!("PPID query: {}", e);
            Quote3Error::NoPlatformCertData
        })?;

    let cd = sig
        .certification_data::<sgx_quote::Qe3CertDataPpid>()
        .map_err(|e| {
            error!("PPID query: {}", e);
            Quote3Error::NoPlatformCertData
        })?;

    // PpidEncryptedRsa2048 / PpidCleartext not supported
    if sig.certification_data_type() != sgx_quote::CertificationDataType::PpidEncryptedRsa3072 {
        error!(
            "PPID query: Invalid certification data type: {:?}",
            sig.certification_data_type()
        );
        return Err(Quote3Error::NoPlatformCertData);
    }

    Ok(cd.clone_owned())
}

/// Get the PCK cert for a QE given its QE certification data.
///
/// Results may be cached.
// This function interacts with the Intel Trusted Services API to get the PCK
// cert. The `OCP_APIM_SUBSCRIPTION_KEY` environment variable must be set with
// the user's API key.
fn get_pckcert(certdata: &sgx_quote::Qe3CertDataPpid) -> Result<PckCertInfo<'static>, Quote3Error> {
    const CPUSVN_LEN: usize = 16;
    const TCBM_LEN: usize = CPUSVN_LEN + 2; // sizeof(CPUSVN) + sizeof(ISVSVN)

    let api_key = std::env::var("OCP_APIM_SUBSCRIPTION_KEY").map_err(|_| {
        error!("OCP_APIM_SUBSCRIPTION_KEY environment variable not set");
        Quote3Error::PlatformLibUnavailable
    })?;

    let url = std::env::var("DCAP_PCKCERT_URL").ok().map_or(
        "https://api.trustedservices.intel.com/sgx/certification/v1/pckcert".into(),
        Cow::from,
    );

    // Send request
    let mut response = reqwest::Client::new()
        .get(&*url)
        .header("Ocp-Apim-Subscription-Key", api_key)
        .query(&[
            ("encrypted_ppid", certdata.ppid.to_hex()),
            ("cpusvn", certdata.cpusvn.to_hex()),
            ("pcesvn", u16_le(certdata.pcesvn).to_hex()),
            ("pceid", u16_le(certdata.pceid).to_hex()),
        ])
        .send()
        .map_err(|e| {
            error!("Failed to obtain PCK certificate: {:?}", e);
            Quote3Error::NoPlatformCertData
        })?;

    // Parse response
    if !response.status().is_success() {
        error!(
            "Failed to obtain PCK certificate, got HTTP status {}",
            response.status()
        );
        return Err(Quote3Error::NoPlatformCertData);
    }

    let tcbm_hex = response
        .headers()
        .get("SGX-TCBm")
        .map_or("".into(), |v| String::from_utf8_lossy(v.as_bytes()));
    let mut tcbm = tcbm_hex.from_hex().unwrap_or_default();
    if tcbm.len() != TCBM_LEN {
        error!("Invalid SGX-TCBm header: {:?}", tcbm_hex);
        return Err(Quote3Error::NoPlatformCertData);
    }
    let tcbm_pcesvn = LE::read_u16(&tcbm[CPUSVN_LEN..]);
    tcbm.truncate(CPUSVN_LEN);

    let mut cert = PckCertInfo {
        certchain: vec![].into(),
        tcbm_cpusvn: tcbm.into(),
        tcbm_pcesvn,
    };

    let buf = cert.certchain.to_mut();
    response.copy_to(buf).map_err(|e| {
        error!("Failed to obtain PCK certificate: {:?}", e);
        Quote3Error::NoPlatformCertData
    })?;
    if buf.last() != Some(&b'\n') {
        buf.push(b'\n');
    }
    let chain = response
        .headers()
        .get("SGX-PCK-Certificate-Issuer-Chain")
        .map_or(&[][..], |v| v.as_bytes());
    buf.extend_from_slice(chain);
    if buf.last() != Some(&b'\n') {
        buf.push(b'\n');
    }

    Ok(cert)
}

#[no_mangle]
pub extern "C" fn sgx_ql_get_quote_config(
    cert_id: &PckCertId,
    p_cert_config: *mut *const Config,
) -> Quote3Error {
    use sgx_quote::{QeId, Qe3CertDataPpid};
    lazy_static! {
        static ref CERTDATA_CACHE: Mutex<HashMap<QeId<'static>, Qe3CertDataPpid<'static>>> =
            Mutex::default();
        static ref CERT_CACHE: Mutex<HashMap<Qe3CertDataPpid<'static>, PckCertInfo<'static>>> =
            Mutex::default();
        static ref ENTERED_ONCE: Mutex<()> = Mutex::default();
    }
    let _ = env_logger::try_init();

    match (|| {
        // Interpret input data
        let certdata;
        match cert_id.crypto_suite {
            PCE_ALG_RSA_OAEP_3072 => unsafe {
                if cert_id.encrypted_ppid_len == 0
                    && cert_id.encrypted_ppid.is_null()
                    && !cert_id.qe3_id.is_null()
                    && cert_id.qe3_id_size == 16
                {
                    // Try to get QE3_ID to PPID mapping
                    let qe3_id = slice::from_raw_parts(cert_id.qe3_id, cert_id.qe3_id_size as _);
                    let guard = CERTDATA_CACHE.lock().unwrap();
                    let cached = guard.get(qe3_id).cloned();
                    drop(guard);
                    if let Some(cd) = cached {
                        debug!("Found cached QE certificate data");
                        certdata = cd
                    } else {
                        // Ideally, we would keep this in a thread-local
                        // variable, but there is no guarantee that the second
                        // call to this function is going to happen on the same
                        // stack.
                        let _guard = ENTERED_ONCE
                            .try_lock()
                            .map_err(|_| Quote3Error::NoPlatformCertData)?;

                        // NB. `CERTDATA_CACHE` must not be locked during this call
                        let quote = get_quote_with_raw_tcb()?;
                        certdata = parse_certdata(qe3_id.into(), &quote)?;
                        CERTDATA_CACHE
                            .lock()
                            .unwrap()
                            .insert(qe3_id.to_owned().into(), certdata.clone());
                    }
                } else if cert_id.encrypted_ppid_len != 384 || cert_id.encrypted_ppid.is_null() {
                    return Err(Quote3Error::InvalidParameter);
                } else {
                    // This code path never gets called by DCAP QL 1.0
                    certdata = Qe3CertDataPpid {
                        ppid: slice::from_raw_parts(
                            cert_id.encrypted_ppid,
                            cert_id.encrypted_ppid_len as _,
                        )
                        .to_owned()
                        .into(),
                        cpusvn: cert_id
                            .platform_cpu_svn
                            .as_ref()
                            .ok_or(Quote3Error::InvalidParameter)?
                            .to_vec()
                            .into(),
                        pcesvn: *cert_id
                            .platform_pce_isv_svn
                            .as_ref()
                            .ok_or(Quote3Error::InvalidParameter)?,
                        pceid: cert_id.pce_id,
                    };
                }
            },
            v => {
                error!("Unrecognized PPID crypto suite: {}", v);
                return Err(Quote3Error::NoPlatformCertData);
            }
        }

        // Create result structure
        let mut cache = CERT_CACHE.lock().unwrap();
        let pckcert = match cache.entry(certdata) {
            Entry::Occupied(e) => {
                debug!("Found cached PCK certificate");
                e.into_mut()
            }
            Entry::Vacant(e) => {
                let pckcert = get_pckcert(e.key())?;
                e.insert(pckcert)
            }
        }
        .clone();

        if pckcert.certchain.len() > u32::max_value() as usize {
            error!(
                "Returned PCK certificate too large: {} bytes",
                pckcert.certchain.len()
            );
            return Err(Quote3Error::NoPlatformCertData);
        }

        let mut buf = Vec::with_capacity(mem::size_of::<Config>() + pckcert.certchain.len());
        buf.resize(mem::size_of::<Config>(), 0);
        buf.extend_from_slice(&pckcert.certchain);
        let mut cert_cpu_svn = [0u8; 16];
        cert_cpu_svn.copy_from_slice(&pckcert.tcbm_cpusvn);

        unsafe {
            let start = Box::into_raw(buf.into_boxed_slice());
            assert_eq!(mem::align_of::<Config>(), mem::align_of_val(&*start));
            ptr::write(
                start as *mut Config,
                Config {
                    version: ConfigVersion::V1,
                    cert_cpu_svn,
                    cert_pce_isv_svn: pckcert.tcbm_pcesvn,
                    cert_data_size: pckcert.certchain.len() as _,
                    cert_data: (start as *const u8).add(mem::size_of::<Config>()),
                },
            );
            *p_cert_config = start as *const Config;
        }
        Ok(())
    })() {
        Ok(()) => Quote3Error::Success,
        Err(v) => v,
    }
}

#[no_mangle]
pub extern "C" fn sgx_ql_free_quote_config(p_cert_config: *const Config) -> Quote3Error {
    let _ = env_logger::try_init();

    match (|| unsafe {
        let cert_data_size = p_cert_config
            .as_ref()
            .ok_or(Quote3Error::InvalidParameter)?
            .cert_data_size;
        let buflen = cert_data_size as usize + mem::size_of::<Config>();
        Box::from_raw(slice::from_raw_parts_mut(p_cert_config as *mut u8, buflen));
        Ok(())
    })() {
        Ok(()) => Quote3Error::Success,
        Err(v) => v,
    }
}
