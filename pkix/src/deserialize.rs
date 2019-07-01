use yasna::{ASN1Result, BERDecodable, parse_der, parse_ber};

/// Trait for objects that can be deserialized from a DER representation.  A
/// wrapper around yasna's `FromBER` trait that sets DER mode and eliminates the
/// `parse_der / from_ber` boilerplate.
pub trait FromDer: BERDecodable {
    fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> ASN1Result<Self> {
        parse_der(der.as_ref(), |r| Self::decode_ber(r))
    }
}

/// Trait for objects that can be deserialized from a DER representation.  A
/// wrapper around yasna's `FromBER` trait that sets DER mode and eliminates the
/// `parse_der / from_ber` boilerplate.
pub trait FromBer: BERDecodable {
    fn decode_ber<T: ?Sized + AsRef<[u8]>>(ber: &T) -> ASN1Result<Self> {
        parse_ber(ber.as_ref(), |r| <Self as BERDecodable>::decode_ber(r))
    }
}

impl<T: BERDecodable> FromDer for T {}
impl<T: BERDecodable> FromBer for T {}
