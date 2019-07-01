#![allow(non_upper_case_globals)]

use pkix::types::ObjectIdentifier;

// Reference for Fortanix OIDs:
// https://fortanix.atlassian.net/wiki/display/PROD/Provisioning+and+Inter-enclave+Communication

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
}
