/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(unused)]

// Crypto suite
pub const PCE_ALG_RSA_OAEP_3072: u8 = 1;

/// Used to describe the PCK Cert for a platform
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PckCertId {
    ///< The QE_ID used to identify the platform for PCK Cert Retrieval
    pub qe3_id: *const u8,
    ///< The Size of hte QE_ID (currenlty 16 bytes)
    pub qe3_id_size: u32,
    ///< Pointer to the platform's raw CPUSVN
    pub platform_cpu_svn: *const [u8; 16],
    ///< Pointer to the platform's raw PCE ISVSVN
    pub platform_pce_isv_svn: *const u16,
    ///< Pointer to the enccrypted PPID (Optional)
    pub encrypted_ppid: *const u8,
    ///< Size of encrytped PPID.
    pub encrypted_ppid_len: u32,
    ///< Crypto algorithm used to encrypt the PPID
    pub crypto_suite: u8,
    ///< Identifies the PCE-Version used to generate the encrypted PPID.
    pub pce_id: u16,
}

/// Contains the valid versions of the config_t data structure.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConfigVersion {
    V1 = 1,
}

/// Contains the certification data used to certify the attestation key and in generating a quote.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Config {
    pub version: ConfigVersion,
    ///< The CPUSVN used to generate the PCK Signature used to certify the attestation key.
    pub cert_cpu_svn: [u8; 16],
    ///< The PCE ISVSVN used to generate the PCK Signature used to certify the attestation key.
    pub cert_pce_isv_svn: u16,
    ///< The size of the buffer pointed to by p_cert_data
    pub cert_data_size: u32,
    ///< The certificaton data used for the quote.
    pub cert_data: *const u8,
}
