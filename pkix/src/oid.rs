#![allow(non_upper_case_globals)]

use std::collections::HashMap;

use super::types::ObjectIdentifier;

lazy_static! {
    // PKCS #1
    pub static ref rsaEncryption: ObjectIdentifier = vec![1, 2, 840, 113549, 1, 1, 1].into();
    pub static ref sha256WithRSAEncryption: ObjectIdentifier = vec![1, 2, 840, 113549, 1, 1, 11].into();

    // X.500 attribute types
    pub static ref commonName: ObjectIdentifier = vec![2, 5, 4, 3].into();
    pub static ref description: ObjectIdentifier = vec![2, 5, 4, 13].into();
    pub static ref dnQualifier: ObjectIdentifier = vec![2, 5, 4, 46].into();

    // X.509 certificate extensions
    pub static ref subjectAltName: ObjectIdentifier = vec![2, 5, 29, 17].into();
    pub static ref basicConstraints: ObjectIdentifier = vec![2, 5, 29, 19].into();
    pub static ref subjectKeyIdentifier: ObjectIdentifier = vec![2, 5, 29, 14].into();
    pub static ref authorityKeyIdentifier: ObjectIdentifier = vec![2, 5, 29, 35].into();
    pub static ref keyUsage: ObjectIdentifier = vec![2, 5, 29, 15].into();

    // PKCS #9 attributes
    pub static ref extensionRequest: ObjectIdentifier = vec![1, 2, 840, 113549, 1, 9, 14].into();

    // Elliptic curves. Reference: RFC5480, 2.1.1.1
    pub static ref ecPublicKey: ObjectIdentifier = vec![1, 2, 840, 10045, 2, 1].into();
    pub static ref SecP192K1: ObjectIdentifier = vec![1, 3, 132, 0, 31].into();
    pub static ref SecP224K1: ObjectIdentifier = vec![1, 3, 132, 0, 32].into();
    pub static ref SecP256K1: ObjectIdentifier = vec![1, 3, 132, 0, 10].into();
    pub static ref NistP192: ObjectIdentifier = vec![1, 2, 840, 10045, 3, 1, 1].into();
    pub static ref NistP224: ObjectIdentifier = vec![1, 3, 132, 0, 33].into();
    pub static ref NistP256: ObjectIdentifier = vec![1, 2, 840, 10045, 3, 1, 7].into();
    pub static ref NistP384: ObjectIdentifier = vec![1, 3, 132, 0, 34].into();
    pub static ref NistP521: ObjectIdentifier = vec![1, 3, 132, 0, 35].into();

    // GOST elliptic curves: RFC4357
    pub static ref Gost256A: ObjectIdentifier = vec![1, 2, 643, 2, 2, 35, 1].into();
    pub static ref Gost256B: ObjectIdentifier = vec![1, 2, 643, 2, 2, 35, 2].into();
    pub static ref Gost256C: ObjectIdentifier = vec![1, 2, 643, 2, 2, 35, 3].into();

    // CMS: RFC5652
    // named as id-ct-contentInfo in the standard.
    pub static ref ctContentInfo : ObjectIdentifier = vec![1, 2, 840, 113549, 1, 9, 16, 1, 6].into();
    pub static ref data: ObjectIdentifier           = vec![1, 2, 840, 113549, 1, 7, 1].into();
    pub static ref signedData: ObjectIdentifier     = vec![1, 2, 840, 113549, 1, 7, 2].into();
    pub static ref envelopedData: ObjectIdentifier  = vec![1, 2, 840, 113549, 1, 7, 3].into();
    pub static ref digestedData: ObjectIdentifier   = vec![1, 2, 840, 113549, 1, 7, 5].into();
    pub static ref encryptedData: ObjectIdentifier  = vec![1, 2, 840, 113549, 1, 7, 6].into();
    // named as id-ct-authData in the standard.
    pub static ref ctAuthData: ObjectIdentifier     = vec![1, 2, 840, 113549, 1, 9, 16, 1, 2].into();

    // KeyEncryptionAlgorithmIdentifier
    pub static ref RSAES_OAEP : ObjectIdentifier    = vec![1, 2, 840, 113549, 1, 1, 7].into();
    pub static ref sha256     : ObjectIdentifier    = vec![2, 16, 840, 1, 101, 3, 4, 2, 1].into();
    pub static ref sha1       : ObjectIdentifier    = vec![1, 3, 14, 3, 2, 26].into();
    pub static ref mgf1       : ObjectIdentifier    = vec![1, 2, 840, 113549, 1, 1, 8].into();
    pub static ref aes128_cbc : ObjectIdentifier    = vec![2, 16, 840, 1, 101, 3, 4, 1, 2].into();
    pub static ref RSASSA_PSS : ObjectIdentifier    = vec![1, 2, 840, 113549, 1, 1, 10].into();
    pub static ref messageDigest: ObjectIdentifier  = vec![1, 2, 840, 113549, 1, 9, 4].into();
}

lazy_static! {
    pub static ref NAME_TO_OID: &'static HashMap<&'static str, ObjectIdentifier> = &MAPPING.1;
    pub static ref OID_TO_NAME: &'static HashMap<ObjectIdentifier, &'static str> = &MAPPING.0;

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
            commonName => CN,
            [2, 5, 4, 4] => SN,
            [2, 5, 4, 5] => serialNumber,
            [2, 5, 4, 6] => C,
            [2, 5, 4, 7] => L,
            [2, 5, 4, 8] => ST,
            [2, 5, 4, 9] => street,
            [2, 5, 4, 10] => O,
            [2, 5, 4, 11] => OU,
            [2, 5, 4, 12] => title,
            description => description,
            [2, 5, 4, 14] => searchGuide,
            [2, 5, 4, 15] => businessCategory,
            [2, 5, 4, 16] => postalAddress,
            [2, 5, 4, 17] => postalCode,
            [2, 5, 4, 18] => postOfficeBox,
            [2, 5, 4, 19] => physicalDeliveryOfficeName,
            [2, 5, 4, 20] => telephoneNumber,
            [2, 5, 4, 21] => telexNumber,
            [2, 5, 4, 22] => teletexTerminalIdentifier,
            [2, 5, 4, 23] => facsimileTelephoneNumber,
            [2, 5, 4, 24] => x121Address,
            [2, 5, 4, 25] => internationaliSDNNumber,
            [2, 5, 4, 26] => registeredAddress,
            [2, 5, 4, 27] => destinationIndicator,
            [2, 5, 4, 28] => preferredDeliveryMethod,
            [2, 5, 4, 29] => presentationAddress,
            [2, 5, 4, 30] => supportedApplicationContext,
            [2, 5, 4, 31] => member,
            [2, 5, 4, 32] => owner,
            [2, 5, 4, 33] => roleOccupant,
            [2, 5, 4, 34] => seeAlso,
            [2, 5, 4, 35] => userPassword,
            [2, 5, 4, 36] => userCertificate,
            [2, 5, 4, 37] => cACertificate,
            [2, 5, 4, 38] => authorityRevocationList,
            [2, 5, 4, 39] => certificateRevocationList,
            [2, 5, 4, 40] => crossCertificatePair,
            [2, 5, 4, 41] => name,
            [2, 5, 4, 42] => GN,
            [2, 5, 4, 43] => initials,
            [2, 5, 4, 44] => generationQualifier,
            [2, 5, 4, 45] => x500UniqueIdentifier,
            dnQualifier => dnQualifier,
            [2, 5, 4, 47] => enhancedSearchGuide,
            [2, 5, 4, 48] => protocolInformation,
            [2, 5, 4, 49] => distinguishedName,
            [2, 5, 4, 50] => uniqueMember,
            [2, 5, 4, 51] => houseIdentifier,
            [2, 5, 4, 52] => supportedAlgorithms,
            [2, 5, 4, 53] => deltaRevocationList,
            [2, 5, 4, 54] => dmdName,
            [2, 5, 4, 65] => pseudonym,
            [2, 5, 4, 72] => role,
            [1, 2, 840, 113549, 1, 9, 1] => emailAddress,

            [2, 5, 29, 14] => subjectKeyIdentifier,
            [2, 5, 29, 15] => keyUsage,
            [2, 5, 29, 17] => subjectAlternativeName,
            [2, 5, 29, 18] => issuerAlternativeName,
            [2, 5, 29, 19] => basicConstraints,
            [2, 5, 29, 20] => cRLNumber,
            [2, 5, 29, 21] => reasonCode,
            [2, 5, 29, 23] => holdInstructionCode,
            [2, 5, 29, 24] => invalidityDate,
            [2, 5, 29, 28] => crlIssuingDistributionPoint,
            [2, 5, 29, 30] => nameConstraints,
            [2, 5, 29, 31] => crlDistributionPoints,
            [2, 5, 29, 32] => certificatePolicies,
            [2, 5, 29, 35] => authorityKeyIdentifier,
            [2, 5, 29, 36] => policyConstraints,
            [2, 5, 29, 37] => extendedKeyUsage,

            [1, 2, 840, 113549, 1, 9, 14] => extensionRequest,

            [1, 3, 6, 1, 5, 5, 7, 3, 1] => keyUsageServerAuth,
            [1, 3, 6, 1, 5, 5, 7, 3, 2] => keyUsageClientAuth,
            [1, 3, 6, 1, 5, 5, 7, 3, 3] => keyUsageCodeSigning,
            [1, 3, 6, 1, 5, 5, 7, 3, 4] => keyUsageEmailProtection,
            [1, 3, 6, 1, 5, 5, 7, 3, 5] => keyUsageIPsecEndSystem,
            [1, 3, 6, 1, 5, 5, 7, 3, 6] => keyUsageIPsecTunnel,
            [1, 3, 6, 1, 5, 5, 7, 3, 7] => keyUsageIPsecUser,
            [1, 3, 6, 1, 5, 5, 7, 3, 8] => keyUsageTimeStamping,
            [1, 3, 6, 1, 5, 5, 7, 3, 9] => keyUsageOCSPSigning,

            [1, 2, 840, 113549, 1, 1, 14] => sha224withRSA,
            [1, 2, 840, 113549, 1, 1, 11] => sha256withRSA,
            [1, 2, 840, 113549, 1, 1, 12] => sha384withRSA,
            [1, 2, 840, 113549, 1, 1, 13] => sha512withRSA,
            [1, 2, 840, 10045, 4, 3, 1] => sha224withECDSA,
            [1, 2, 840, 10045, 4, 3, 2] => sha256withECDSA,
            [1, 2, 840, 10045, 4, 3, 3] => sha384withECDSA,
            [1, 2, 840, 10045, 4, 3, 4] => sha512withECDSA,

            [1, 3, 101, 110] => x25519,
            [1, 3, 101, 111] => x448,
            [1, 3, 101, 112] => ed25519,
            [1, 3, 101, 113] => ed448,
        }

        (oid_to_name, name_to_oid)
    };
}
