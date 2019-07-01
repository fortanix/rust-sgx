use yasna::{ASN1Result, FromBER, parse_der, parse_ber};

/// Trait for objects that can be deserialized from a DER representation.  A
/// wrapper around yasna's `FromBER` trait that sets DER mode and eliminates the
/// `parse_der / from_ber` boilerplate.
pub trait FromDer: FromBER {
    fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> ASN1Result<Self> {
        parse_der(der.as_ref(), |r| Self::from_ber(r))
    }
}

/// Trait for objects that can be deserialized from a DER representation.  A
/// wrapper around yasna's `FromBER` trait that sets DER mode and eliminates the
/// `parse_der / from_ber` boilerplate.
pub trait FromBer: FromBER {
    fn from_ber<T: ?Sized + AsRef<[u8]>>(ber: &T) -> ASN1Result<Self> {
        parse_ber(ber.as_ref(), |r| <Self as FromBER>::from_ber(r))
    }
}

impl<T: FromBER> FromDer for T {}
impl<T: FromBER> FromBer for T {}
