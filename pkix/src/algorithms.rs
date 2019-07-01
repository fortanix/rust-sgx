use derives::*;
use oid;

/* An algorithm identifier is a sequence containing OID
 * Followed by optional components based on the algorithm
 * If nothing beyond OID is required, we need to write_null()
*/
macro_rules! define_algorithm_identifier {
    (
        $($variant:ident = $val:expr),*,
    ) => {
        enum_oid! {
            AlgorithmIdentifierType {
                $($variant = $val),*,
            }
        }

        impl_content_with_associated_type! {
            AlgorithmIdentifier : Sequence => AlgorithmIdentifierType {
                $($variant),*,
            }
        }
    }
}

// These are identifiers without furthur description
macro_rules! impl_null_desc_algorithm_identifier {
    (
        $($variant:ident),*,
    ) => {
        $(
            #[derive(Clone, Debug, Eq, PartialEq, Hash)]
            #[allow(non_camel_case_types)]
            pub struct $variant{}
            impl DerWrite for $variant {
                fn write(&self, writer: DERWriter) {
                    writer.write_null();
                }
            }
            impl BERDecodable for $variant {
                fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                    reader.read_null().and_then(|_| Ok($variant{}))
                }
            }
        )*
    }
}

macro_rules! define_algorithm {
    ($name:ident => $Ty:ident {
        $($variant:ident = $val:expr),*,
     }
    ) => {
        enum_oid! {
            $Ty {
                $($variant = $val),*,
            }
        }

        impl_content_with_associated_type! {
            $name : Sequence => $Ty {
                $($variant),*,
            }
        }
    }
}

impl_null_desc_algorithm_identifier! {
    sha256,
    sha1,
}

define_algorithm_identifier! {
    sha256 = oid::sha256,
    sha1 = oid::sha1,
    mgf1 = oid::mgf1,
    aes128_cbc = oid::aes128_cbc,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[allow(non_camel_case_types)]
pub struct mgf1 {}

// mfg1's following content is always the AlgorithmIdentifier for sha1.
impl DerWrite for mgf1 {
    fn write(&self, writer: DERWriter) {
        let algo = sha1 {};
        &algo.write(writer);
    }
}

impl BERDecodable for mgf1 {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        <sha1 as BERDecodable>::decode_ber(reader).and_then(|_| Ok(mgf1 {}))
    }
}

enum_subtype! {
    ContentEncryptionAlgorithm => AlgorithmIdentifier {
        aes128_cbc,
    }
}

const CMS_128_IV_LEN : usize = 16;
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[allow(non_camel_case_types)]
pub struct aes128_cbc {
    pub iv: [u8; 16],
}

impl aes128_cbc {
    pub fn new(iv: &[u8]) -> ASN1Result<Self> {
        if iv.len() != CMS_128_IV_LEN {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        let mut algo_iv : [u8; CMS_128_IV_LEN] = [0; CMS_128_IV_LEN];
        algo_iv.copy_from_slice(iv);
        Ok(aes128_cbc{iv : algo_iv})
    }
}

impl DerWrite for aes128_cbc {
    fn write(&self, writer: DERWriter) {
        writer.write_bytes(&self.iv);
    }
}

impl BERDecodable for aes128_cbc {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_bytes().and_then(|iv| aes128_cbc::new(&iv))
    }
}

enum_subtype! {
    HashAlgorithm => AlgorithmIdentifier {
        sha256,
    }
}

enum_subtype! {
    MaskGenAlgorithm => AlgorithmIdentifier {
        mgf1,
    }
}

enum_subtype! {
    DigestAlgorithmIdentifier => AlgorithmIdentifier {
        sha256,
    }
}
derive_set_of! {
    DigestAlgorithmIdentifier => DigestAlgorithmIdentifiers
}

//RSAES_OAEP
#[allow(non_camel_case_types)]
define_algorithm! {
    KeyEncryptionAlgorithm => KeyEncryptionAlgorithmType {
        RSAES_OAEP = oid::RSAES_OAEP,
    }
}
// rfc3560#section-2.2
//rfc3447#appendix-A.2.1
derive_sequence! {
    RSAES_OAEP {
        hashAlgorithm    :    [0] EXPLICIT : HashAlgorithm,
        maskGenAlgorithm :    [1] EXPLICIT : MaskGenAlgorithm,
    }
}

#[allow(non_camel_case_types)]
define_algorithm! {
    SignatureAlgorithm  => SignatureAlgorithmType {
        RSASSA_PSS = oid::RSASSA_PSS,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SaltLength(u64);

impl From<u64> for SaltLength {
    fn from(n: u64) -> SaltLength {
        SaltLength(n)
    }
}

impl From<SaltLength> for u64 {
    fn from(s: SaltLength) -> u64 {
        let SaltLength(n) = s;
        n
    }
}

impl BERDecodable for SaltLength {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_u64().and_then(|n| Ok(n.into()))
    }
}

impl DerWrite for SaltLength {
    fn write(&self, writer: DERWriter) {
        // self is essentially an integer, clone should be trivial.
        u64::from(self.clone()).write(writer)
    }
}

// rfc3560#section-2.2
derive_sequence! {
    RSASSA_PSS {
        hashAlgorithm : [0] EXPLICIT : HashAlgorithm,
        maskAlgorithm : [1] EXPLICIT : MaskGenAlgorithm,
        saltLength    : [2] EXPLICIT : SaltLength,
    }
}
