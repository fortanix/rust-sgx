/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(non_upper_case_globals)]

use std::collections::HashMap;
use pkix::types::ObjectIdentifier;

lazy_static!{
    // Fortanix attribute types
    pub static ref sgxCpusvn: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 1].into();
    pub static ref sgxMiscselect: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 2].into();
    pub static ref sgxAttributes: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 3].into();
    pub static ref sgxMrenclave: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 4].into();
    pub static ref sgxMrsigner: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 5].into();
    pub static ref sgxIsvprodid: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 6].into();
    pub static ref sgxIsvsvn: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 7].into();
    pub static ref sgxReportdata: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 8].into();

    // Fortanix CSR attributes / certificate extensions
    pub static ref attestationInlineSgxLocal: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 1, 1].into();
    pub static ref attestationInlineFqpeFlag: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 1, 2].into();
    pub static ref attestationEmbeddedFqpe: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 1].into();
    pub static ref attestationEmbeddedIntelQuote: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 2].into();
    pub static ref attestationEmbeddedIasReport: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 3].into();

    pub static ref attestationEmbeddedQe3Quote: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 4].into();
    pub static ref attestationDcap: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 5].into();

    // Fortanix public key algorithm identifiers
    pub static ref ledaCrypt_34_0: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 4, 1].into();
    pub static ref round5_5pke_0d: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 4, 2].into();
    pub static ref lms_15_10_sha256: ObjectIdentifier = vec![1, 3, 6, 1, 4, 1, 49690, 4, 3].into();

    // Intel SGX OID namespaces:
    // https://download.01.org/intel-sgx/sgx-dcap/1.10/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.4.pdf
    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QVL/Src/AttestationParsers/src/ParserUtils.h#L57
    pub static ref SGX_EXTENSION:                     ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1].into();
    pub static ref SGX_EXTENSION_PPID:                ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 1].into();
    pub static ref SGX_EXTENSION_TCB:                 ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2].into();
    pub static ref SGX_EXTENSION_TCB_COMP01_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 1].into();
    pub static ref SGX_EXTENSION_TCB_COMP02_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 2].into();
    pub static ref SGX_EXTENSION_TCB_COMP03_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 3].into();
    pub static ref SGX_EXTENSION_TCB_COMP04_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 4].into();
    pub static ref SGX_EXTENSION_TCB_COMP05_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 5].into();
    pub static ref SGX_EXTENSION_TCB_COMP06_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 6].into();
    pub static ref SGX_EXTENSION_TCB_COMP07_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 7].into();
    pub static ref SGX_EXTENSION_TCB_COMP08_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 8].into();
    pub static ref SGX_EXTENSION_TCB_COMP09_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 9].into();
    pub static ref SGX_EXTENSION_TCB_COMP10_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 10].into();
    pub static ref SGX_EXTENSION_TCB_COMP11_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 11].into();
    pub static ref SGX_EXTENSION_TCB_COMP12_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 12].into();
    pub static ref SGX_EXTENSION_TCB_COMP13_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 13].into();
    pub static ref SGX_EXTENSION_TCB_COMP14_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 14].into();
    pub static ref SGX_EXTENSION_TCB_COMP15_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 15].into();
    pub static ref SGX_EXTENSION_TCB_COMP16_SVN:      ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 16].into();
    pub static ref SGX_EXTENSION_TCB_PCESVN:          ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 17].into();
    pub static ref SGX_EXTENSION_TCB_CPUSVN:          ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 2, 18].into();
    pub static ref SGX_EXTENSION_PCEID:               ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 3].into();
    pub static ref SGX_EXTENSION_FMSPC:               ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 4].into();
    pub static ref SGX_EXTENSION_SGX_TYPE:            ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 5].into();
    pub static ref SGX_EXTENSION_PLATFORM_INSTANCE_ID: ObjectIdentifier = vec![1, 2, 840, 113741, 1, 13, 1, 6].into();
    pub static ref SGX_EXTENSION_CONFIGURATION:       ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 7].into();
    pub static ref SGX_EXTENSION_CONF_DYNAMIC_PLATFORM: ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 7, 1].into();
    pub static ref SGX_EXTENSION_CONF_CACHED_KEYS:    ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 7, 2].into();
    pub static ref SGX_EXTENSION_CONF_SMT_ENABLED:    ObjectIdentifier  = vec![1, 2, 840, 113741, 1, 13, 1, 7, 3].into();
    
    static ref MAPPING: (HashMap<ObjectIdentifier, &'static str>, HashMap<&'static str, ObjectIdentifier>) = {
        let mut name_to_oid = HashMap::new();
        let mut oid_to_name = HashMap::new();

        macro_rules! oid_names {
            ([$($component:expr),*] => $name:ident, $($rest:tt)*) => (
                let oid: ObjectIdentifier = vec![$($component),*].into();
                name_to_oid.insert(stringify!($name), oid.clone());
                oid_to_name.insert(oid, stringify!($name));
                oid_names!($($rest)*);
            );
            ($oid:ident => $name:ident, $($rest:tt)*) => (
                name_to_oid.insert(stringify!($name), $oid.clone());
                oid_to_name.insert($oid.clone(), stringify!($name));
                oid_names!($($rest)*);
            );
            () => ();
        }

        oid_names! {
            [1, 2, 840, 113741, 1, 13, 1] => SGX_EXTENSION,
            [1, 2, 840, 113741, 1, 13, 1, 1] => SGX_EXTENSION_PPID ,
            [1, 2, 840, 113741, 1, 13, 1, 2] => SGX_EXTENSION_TCB,
            [1, 2, 840, 113741, 1, 13, 1, 2, 1] => SGX_EXTENSION_TCB_COMP01_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 2] => SGX_EXTENSION_TCB_COMP02_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 3] => SGX_EXTENSION_TCB_COMP03_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 4] => SGX_EXTENSION_TCB_COMP04_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 5] => SGX_EXTENSION_TCB_COMP05_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 6] => SGX_EXTENSION_TCB_COMP06_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 7] => SGX_EXTENSION_TCB_COMP07_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 8] => SGX_EXTENSION_TCB_COMP08_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 9] => SGX_EXTENSION_TCB_COMP09_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 10] => SGX_EXTENSION_TCB_COMP10_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 11] => SGX_EXTENSION_TCB_COMP11_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 12] => SGX_EXTENSION_TCB_COMP12_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 13] => SGX_EXTENSION_TCB_COMP13_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 14] => SGX_EXTENSION_TCB_COMP14_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 15] => SGX_EXTENSION_TCB_COMP15_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 16] => SGX_EXTENSION_TCB_COMP16_SVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 17] => SGX_EXTENSION_TCB_PCESVN,
            [1, 2, 840, 113741, 1, 13, 1, 2, 18] => SGX_EXTENSION_TCB_CPUSVN,
            [1, 2, 840, 113741, 1, 13, 1, 3] => SGX_EXTENSION_PCEID,
            [1, 2, 840, 113741, 1, 13, 1, 4] => SGX_EXTENSION_FMSPC,
            [1, 2, 840, 113741, 1, 13, 1, 5] => SGX_EXTENSION_SGX_TYPE,
            [1, 2, 840, 113741, 1, 13, 1, 6] => SGX_EXTENSION_PLATFORM_INSTANCE_ID,
            [1, 2, 840, 113741, 1, 13, 1, 7] => SGX_EXTENSION_CONFIGURATION,
            [1, 2, 840, 113741, 1, 13, 1, 7, 1] => SGX_EXTENSION_CONF_DYNAMIC_PLATFORM,
            [1, 2, 840, 113741, 1, 13, 1, 7, 2] => SGX_EXTENSION_CONF_CACHED_KEYS,
            [1, 2, 840, 113741, 1, 13, 1, 7, 3] => SGX_EXTENSION_CONF_SMT_ENABLED,
        }

        (oid_to_name, name_to_oid)
    };
}
