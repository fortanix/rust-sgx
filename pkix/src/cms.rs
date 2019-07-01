use oid;
use std::collections::{HashMap, HashSet};
use std::convert::AsRef;
use derives::*;
use algorithms::*;

macro_rules! define_signed_attributes {
    (
        $($variant:ident = $val:expr),*,
    ) => {
        enum_oid! {
            SignedAttributeType {
                $($variant = $val),*,
            }
        }

        impl_content_with_associated_type! {
            SignedAttribute : Sequence => SignedAttributeType {
                $($variant),*,
            }
        }
        pub trait TryFromSignedAttr : Sized + Clone {
            fn try_from(attr: &SignedAttribute) -> Result<Self, ASN1Error>;
        }
        $(
            impl TryFromSignedAttr for $variant {
                fn try_from(attr: &SignedAttribute) -> Result<Self, ASN1Error> {
                    match attr {
                        &SignedAttribute::$variant(ref attr) => Ok(attr.clone()),
                        _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                    }
                }
            }
          )*
        pub fn get_attrs<T:TryFromSignedAttr>(signed_attrs: &Vec<SignedAttribute>) -> Vec<T> {
            let mut ret = vec![];
            for attr in signed_attrs.iter() {
                match T::try_from(attr) {
                    Ok(attr) => ret.push(attr.clone()),
                    _ => {}
                }
             }
             ret
        }
    }
}

macro_rules! define_content {
    (
        $($variant:ident = $val:expr),*,
    ) => {
        enum_oid! {
            ContentType {
                $($variant = $val),*,
            }
        }

        impl_content_with_associated_type! {
            ContentInfo => ContentType {
                $($variant),*,
            }
        }

        // rfc5652#section-5.2.1 Allows EncapsulatedContentInfo to use.
        // oids in addition to those in ContentInfo.
        // We do not need them for now.
        // We do not need to implement DerWrite  and BERDecodable EncapsulatedContentInfo.
        define_content_with_associated_type! {
            EncapsulatedContentInfo  => ContentType {
                $($variant),*,
            }
        }
        impl_content_with_associated_type! {
            EncapsulatedContentInfoOctets => ContentType {
                $($variant(Octets)),*,
            }
        }

        impl EncapsulatedContentInfoOctets {
            pub fn get_octets(&self) -> &[u8] {
                match self {
                    $(&EncapsulatedContentInfoOctets::$variant(ref var) => &var.data),*,
                }
            }
        }

        impl From<EncapsulatedContentInfo> for EncapsulatedContentInfoOctets {
            fn from(info : EncapsulatedContentInfo) -> EncapsulatedContentInfoOctets {
                match info {
                    $(EncapsulatedContentInfo::$variant(inner_data) => {
                         let data = inner_data.to_der();
                         EncapsulatedContentInfoOctets::$variant(Octets{data})
                     })*
                }
            }
        }
        impl From<EncapsulatedContentInfoOctets> for ASN1Result<EncapsulatedContentInfo> {
            fn from(encapsulated_octets : EncapsulatedContentInfoOctets) -> ASN1Result<EncapsulatedContentInfo> {
                match encapsulated_octets {
                    $(EncapsulatedContentInfoOctets::$variant(octets) => {
                         <$variant as FromBer>::decode_ber(&octets)
                         .and_then(|inner_data| {
                                      Ok(EncapsulatedContentInfo::$variant(inner_data))
                                  })
                     })*
                }
            }
        }

        impl DerWrite for EncapsulatedContentInfoOctets {
            fn write(&self, writer: DERWriter) {
                writer.write_sequence(|writer| {
                    self.get_type().write(writer.next());
                    writer.next().write_tagged(Tag::context(0), |writer| {
                        self.content_writer().write(writer);
                    });
                })
             }
        }

        impl BERDecodable for EncapsulatedContentInfoOctets {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_sequence(|seq_reader| {
                    let content_type = <ContentType as BERDecodable>::decode_ber(seq_reader.next())?;
                    seq_reader.next().read_tagged(Tag::context(0), |reader| {
                        EncapsulatedContentInfoOctets::content_reader(content_type, reader)
                    })
                })
            }
        }
        impl DerWrite for ContentInfo {
            fn write(&self, writer: DERWriter) {
                writer.write_sequence(|writer| {
                    writer.next().write_oid(&oid::ctContentInfo);
                    writer.next().write_sequence(|writer| {
                        self.get_type().write(writer.next());
                        self.content_writer().write(writer.next());
                    })
                })
             }
        }

        impl BERDecodable for ContentInfo {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    if oid != *oid::ctContentInfo {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }
                    reader.next().read_sequence(|seq_reader| {
                        let content_type = <ContentType as BERDecodable>::decode_ber(seq_reader.next())?;
                        ContentInfo::content_reader(content_type, seq_reader.next())
                    })
                })
            }
        }
    }
}


// CMS spec has a lot of versioned sequences.
// A versioned sequence is a data structure
// serialized as an ASN1 sequence, beginning with
// an integer indicating CMSVersion.
// CMSVersion indicates which of the optional
// subfields are present.
// For type safety its best to create different sub-types
// for each version.
macro_rules! versionedSeq {
    ($name:ident {
            $($variant:ident = $val:ident),*,
     }) => {
        impl_content_with_associated_type! {
            $name : Sequence TypeEmbedded => CMSVersion {
                $($variant = $val),*,
            }
        }
    }
}


// sec-10.2.5
define_version! {
    CMSVersion {
        V0 = 0,
        V1 = 1,
        V2 = 2,
        V3 = 3,
        V4 = 4,
        V5 = 5,
    }
}

// We could define `id-mgrZoneSealedProto` as a custom ContentType here.
// Most likely, our custom content type will not take place of SignedData,
// or, EnvelopedData. So, it would be best to treat encryptedContent as
// any thing that could be written as a DER and has an oid (supports HasOid).
// and, pass `id-mgrZoneSealedProto` as a type that supports the above.
define_content! {
    SignedData = oid::signedData,
    EnvelopedData = oid::envelopedData,
}

versionedSeq! {
    SignedData {
        SignedDataV3 = V3,
    }
}

derive_sequence! {
    SignedDataV3 : Subsequence {
        // TODO support multiple algorithms
        digestAlgorithms : [_] UNTAGGED : DigestAlgorithmIdentifiers,
        encapContentInfo : [_] UNTAGGED : EncapsulatedContentInfoOctets,
        certificates     : [0] IMPLICIT : Certificates,
        signerInfos      : [_] UNTAGGED : SignerInfos
    }
}


// Constructing SignedData is complex.Also certiain things have to be ensured at run time.
// For example a SignerInfo should not use a digest algorithm not mentioned in digestAlgorithms.

derive_set_of! {
    Vec<u8> => Certificates
}

versionedSeq! {
    SignerInfo {
        SignerInfoV3 = V3,
    }
}
derive_set_of! {
    SignerInfo => SignerInfos
}
derive_sequence! {
    SignerInfoV3 : Subsequence {
        sid                : [0] IMPLICIT : Vec<u8>,
        digestAlgorithm    : [_] UNTAGGED : DigestAlgorithmIdentifier,
        signedAttrs        : [0] IMPLICIT : SignedAttributes,
        signatureAlgorithm : [_] UNTAGGED : SignatureAlgorithm,
        signature          : [_] UNTAGGED : Vec<u8>,
    }
}


define_signed_attributes! {
          SignedAttributeContent = oid::ctContentInfo,
          SignedAttributeMessageDigest = oid::messageDigest,
}
derive_set! {
 SignedAttribute => SignedAttributes
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedAttributeContent {
    pub content_type: ContentType,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SignedAttributeMessageDigest {
    pub digest: Vec<u8>,
}

versionedSeq! {
    EnvelopedData {
        EnvelopedDataV2 = V2,
    }
}

derive_sequence! {
    EnvelopedDataV2 : Subsequence {
        recipientInfos : KeyTransRecipientInfos,
        encryptedContentInfo : EncryptedContentInfo,
        encryptedContent : Vec<u8>,
    }
}

// TODO Implement CHOICE!!
versionedSeq! {
    KeyTransRecipientInfo {
         KeyTransRecipientInfoV2 = V2,
    }
}

derive_sequence! {
    KeyTransRecipientInfoV2 : Subsequence {
       // OCTET STRING sec:6.2.2
       subjectKeyIdentifier : Vec<u8>,
       algorithm : KeyEncryptionAlgorithm,
       // OCTET STRING
       encryptedKey : Vec<u8>,
    }
}

derive_set! {
    KeyTransRecipientInfo => KeyTransRecipientInfos
}

derive_sequence! {
    EncryptedContentInfo {
        contentType : ObjectIdentifier,
        contentEncryptionAlgorithm : ContentEncryptionAlgorithm,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Octets {
    data: Vec<u8>,
}


// Supported Algorithms

impl DerWrite for Octets {
    fn write(&self, writer: DERWriter) {
        //TODO check if it becomes octet string.
        writer.write_bytes(&self.data);
    }
}

impl BERDecodable for Octets {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_bytes().and_then(|data| Ok(Octets { data }))
    }
}

impl AsRef<[u8]> for Octets {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl DerWrite for SignedAttributeContent {
    fn write(&self, writer: DERWriter) {
        writer.write_set_of(|writer| {
            self.content_type.write(writer.next());
        })
    }
}

impl BERDecodable for SignedAttributeContent {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let mut content_type: Vec<ContentType> = vec![];
        reader.read_set_of(|reader| {
            let content_type_elem = <ContentType as BERDecodable>::decode_ber(reader)?;
            content_type.push(content_type_elem);
            Ok(())
        })?;
        if content_type.len() == 1 {
            Ok(SignedAttributeContent {
                content_type: content_type.pop().unwrap(),
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}

impl DerWrite for SignedAttributeMessageDigest {
    fn write(&self, writer: DERWriter) {
        writer.write_set_of(|writer| {
            self.digest.write(writer.next());
        })
    }
}

impl BERDecodable for SignedAttributeMessageDigest {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let mut digest: Vec<Vec<u8>> = vec![];
        reader.read_set_of(|reader| {
            let digest_elem = <Vec<u8> as BERDecodable>::decode_ber(reader)?;
            digest.push(digest_elem);
            Ok(())
        })?;
        if digest.len() == 1 {
            Ok(SignedAttributeMessageDigest {
                digest: digest.pop().unwrap(),
            })
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}

// TODO Better Error handling.
#[allow(dead_code)]
pub struct SignedDataV3Builder<E> {
    signed_data: SignedDataV3,
    digest_algorithm_table: HashMap<DigestAlgorithmIdentifier, Box<dyn Fn(&[u8]) -> Result<Vec<u8>, E>>>,
}
impl <E> SignedDataV3Builder<E> {
    pub fn new<T: Into<EncapsulatedContentInfoOctets>>(
        encapsulated_content: T,
    ) -> SignedDataV3Builder<E> {
        let signed_data = SignedDataV3 {
            digestAlgorithms: vec![].into(),
            encapContentInfo: encapsulated_content.into(),
            certificates: vec![].into(),
            signerInfos: vec![].into(),
        };
        let digest_algorithm_table = HashMap::new();
        SignedDataV3Builder {
            signed_data,
            digest_algorithm_table,
        }
    }

    pub fn add_digest_algorithm<D: Into<DigestAlgorithmIdentifier>>(
        mut self,
        identifier: D,
        call_back: Box<dyn Fn(&[u8]) -> Result<Vec<u8>, E>>,
    ) -> ASN1Result<SignedDataV3Builder<E>> {
        let identifier = identifier.into();
        if self.digest_algorithm_table.contains_key(&identifier) {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        self.signed_data.digestAlgorithms.push(identifier.clone());
        self.digest_algorithm_table.insert(identifier, call_back);
        Ok(self)
    }

    // we need to add a certificate(optionally a chain) for the verifier to be able to verify the signed content
    // add_signer_info can not verify that the chain or certificate matches the signing key since signing happens via
    // a call back.
    // We accept certificates in their DER form.
    // By builder adds contentType and messageDigest type attributes.
    pub fn add_signer_info_v3<'a, V, A, D, S, C, Er>(
        mut self,
        certificates: C,
        sid: V,
        digest_algorithm: D,
        signed_attrs: S,
        signature_algorithm: A,
        mut sign_call_back: Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, Er> + 'a>,
    ) -> ASN1Result<SignedDataV3Builder<E>>
    where
        V: Into<Vec<u8>>,
        A: Into<SignatureAlgorithm>,
        D: Into<DigestAlgorithmIdentifier>,
        S: Into<SignedAttributes>,
        C: Into<Certificates>,
    {
        //SignerInfoV3

        let digest_algorithm_identifier = digest_algorithm.into();

        let attr_content = SignedAttributeContent {
            content_type: self.signed_data.encapContentInfo.get_type(),
        };


        let attr_message_digest = self.digest_algorithm_table
                                  .get(&digest_algorithm_identifier)
                                  .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))
                                  .and_then(|func|
                                       func(self.signed_data.encapContentInfo.get_octets())
                                       .map(|digest| SignedAttributeMessageDigest { digest: digest })
                                       .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid)))?;

        let mut signed_attrs = signed_attrs.into();
        signed_attrs.elements.push(attr_content.into());
        signed_attrs.elements.push(attr_message_digest.into());
        signed_attrs.verify_unique()?;
        let signed_attrs_der = construct_der(|w| signed_attrs.write(w));
        let signature = sign_call_back(&signed_attrs_der)
            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let signer_info = SignerInfoV3 {
            sid: sid.into(),
            digestAlgorithm: digest_algorithm_identifier,
            signedAttrs: signed_attrs,
            signatureAlgorithm: signature_algorithm.into(),
            signature: signature,
        };
        let mut cur_certs = certificates.into();
        self.signed_data
            .certificates
            .elements
            .append(&mut cur_certs.elements);
        self.signed_data
            .signerInfos
            .elements
            .push(signer_info.into());
        Ok(self)
    }

    pub fn sign(self) -> ASN1Result<SignedDataV3> {
        // We need atleast one signer info.
        // Also for V3, certificate must be present and we need SignerInfoV3
        if self.signed_data.signerInfos.elements.len() == 0
            || self.signed_data.certificates.elements.len() == 0
        {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }
        Ok(self.signed_data)
    }
}

impl SignerInfoV3 {
    #[allow(non_camel_case_types, non_snake_case)]
    pub fn new<V, D, S, A, U>(
        sid: V,
        digestAlgorithm: D,
        signedAttrs: S,
        signatureAlgorithm: A,
        signature: Option<U>,
    ) -> ASN1Result<SignerInfoV3>
    where
        V: Into<Vec<u8>>,
        A: Into<SignatureAlgorithm>,
        D: Into<DigestAlgorithmIdentifier>,
        S: Into<SignedAttributes>,
        U: Into<Vec<u8>>,
    {
        let signedAttrs = signedAttrs.into();
        signedAttrs.verify_unique()?;
        Ok(SignerInfoV3 {
            sid: sid.into(),
            digestAlgorithm: digestAlgorithm.into(),
            signedAttrs: signedAttrs,
            signatureAlgorithm: signatureAlgorithm.into(),
            signature: match signature {
                Some(sig) => sig.into(),
                None => vec![],
            },
        })
    }
}

impl SignedAttributes {
    pub fn verify_unique(&self) -> ASN1Result<()> {
        /* Only One attribute of a type should be queued in */
        let mut attr_set = HashSet::new();
        for attr in self.elements.iter() {
            let attr_type = attr.get_type();
            if attr_set.contains(&attr_type) {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            attr_set.insert(attr_type);
        }
        Ok(())
    }
}

impl EnvelopedDataV2 {
    #[allow(non_camel_case_types, non_snake_case)]
    pub fn new(
        recipientInfosV2: Vec<KeyTransRecipientInfoV2>,
        encryptedContentInfo: EncryptedContentInfo,
        encryptedContent: &[u8],
    ) -> EnvelopedDataV2 {
        let mut recipientInfos: KeyTransRecipientInfos = vec![].into();
        for info in recipientInfosV2 {
            recipientInfos.push::<KeyTransRecipientInfo>(info.into());
        }
        EnvelopedDataV2 {
            recipientInfos,
            encryptedContentInfo,
            encryptedContent: encryptedContent.into(),
        }
    }
}


impl KeyTransRecipientInfoV2 {
    #[allow(non_camel_case_types, non_snake_case)]
    pub fn new<T: Into<Vec<u8>>, A: Into<KeyEncryptionAlgorithm>>(
        subjectKeyIdentifier: T,
        algorithm: A,
        encryptedKey: &[u8],
    ) -> KeyTransRecipientInfoV2 {
        KeyTransRecipientInfoV2 {
            subjectKeyIdentifier: subjectKeyIdentifier.into(),
            algorithm: algorithm.into(),
            encryptedKey: encryptedKey.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yasna::{construct_der, parse_der, BERDecodable};

    #[test]
    fn enum_from_oid() {
        assert_eq!(
            ContentType::try_from_oid(oid::signedData.clone()).unwrap(),
            ContentType::SignedData
        );
        assert_eq!(
            ContentType::try_from_oid(oid::envelopedData.clone()).unwrap(),
            ContentType::EnvelopedData
        );
        let content_type = ContentType::EnvelopedData;
        let der = construct_der(|w| content_type.write(w));
        assert_eq!(
            parse_der(&der, |r| <ContentType as BERDecodable>::decode_ber(r)).unwrap(),
            content_type
        );
    }
}
