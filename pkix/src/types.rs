use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, BERDecodable, PCBit};
use yasna::tags::*;
pub use yasna::models::{ObjectIdentifier, ParseOidError, TaggedDerValue};
use std::borrow::Cow;
use std::str;
use std::fmt;
use rustc_serialize::hex::ToHex;

use {DerWrite, oid};

pub trait HasOid {
    fn oid() -> &'static ObjectIdentifier;
}

pub trait SignatureAlgorithm {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RsaPkcs15<H>(pub H);

impl<H> SignatureAlgorithm for RsaPkcs15<H> {}

impl<'a> SignatureAlgorithm for DerSequence<'a> {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Sha256;

/// sha256WithRSAEncryption
impl DerWrite for RsaPkcs15<Sha256> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid::sha256WithRSAEncryption);
            writer.next().write_null();
        })
    }
}

impl BERDecodable for RsaPkcs15<Sha256> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;
            seq_reader.next().read_null()?;
            if oid == *oid::sha256WithRSAEncryption {
                Ok(RsaPkcs15(Sha256))
            } else {
                Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Name {
    // The actual ASN.1 type is Vec<HashSet<(ObjectIdentifier, TaggedDerValue)>>.
    // However, having more than one element in the set is extremely uncommon.
    //
    // On deserialization, we flatten the structure. This results in
    // technically non-compliant equality testing (RFC 5280, §7.1). On
    // serialization, we always put each `AttributeTypeAndValue` in its own
    // set.
    //
    // Additional discussion in https://github.com/zmap/zlint/issues/220
    pub value: Vec<(ObjectIdentifier, TaggedDerValue)>,
}

impl Name {
    pub fn get(&self, oid: &ObjectIdentifier) -> Option<&TaggedDerValue> {
        self.value.iter().find(|v| v.0 == *oid).map(|v| &v.1)
    }
}

fn format_oid(oid: &ObjectIdentifier) -> String {
    match oid::OID_TO_NAME.get(oid) {
        Some(o) => o.to_string(),
        None => oid.components().iter().map(|c| c.to_string()).collect::<Vec<_>>().join(".")
    }
}

fn format_der(der: &TaggedDerValue) -> String {
    if der.pcbit() == PCBit::Constructed {
        der.value().to_hex()
    } else {
        match der.tag() {
            TAG_NUMERICSTRING | TAG_PRINTABLESTRING | TAG_IA5STRING | TAG_UTF8STRING => {
                String::from_utf8_lossy(&der.value()).to_string()
            }
            _ => {
                der.value().to_hex()
            }
        }
    }
}

fn format_rdr(rdr: &(ObjectIdentifier, TaggedDerValue)) -> String {
    format!("{}={}", format_oid(&rdr.0), format_der(&rdr.1))
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value.iter().map(|rdr| format_rdr(rdr)).collect::<Vec<_>>().join(", "))?;
        Ok(())
    }
}

impl From<Vec<(ObjectIdentifier, TaggedDerValue)>> for Name {
    fn from(b: Vec<(ObjectIdentifier, TaggedDerValue)>) -> Name {
        Name { value: b }
    }
}

impl DerWrite for Name {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for &(ref oid, ref value) in &self.value {
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        oid.write(writer.next());
                        value.write(writer.next());
                    });
                });
            }
        });
    }
}

impl BERDecodable for Name {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let mut vals = Vec::<(ObjectIdentifier, TaggedDerValue)>::new();

            loop {
                let res = seq_reader.read_optional(|r| {
                    r.read_set_of(|r| {
                        let val = r.read_sequence(|r| {
                            let oid = ObjectIdentifier::decode_ber(r.next())?;
                            let value = TaggedDerValue::decode_ber(r.next())?;
                            Ok((oid, value))
                        })?;
                        vals.push(val);
                        Ok(())
                    })
                });
                match res {
                    Ok(Some(())) => {},
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(Name { value: vals })
        })
    }
}

#[derive(Debug, Clone)]
pub enum NameComponent {
    Str(String),
    Bytes(Vec<u8>)
}

impl NameComponent {
    pub fn bytes(&self) -> Option<&[u8]> {
        match *self {
            NameComponent::Bytes(ref v) => Some(&v),
            _ => None,
        }
    }
}

impl From<String> for NameComponent {
    fn from(s: String) -> NameComponent {
        NameComponent::Str(s)
    }
}

impl From<Vec<u8>> for NameComponent {
    fn from(b: Vec<u8>) -> NameComponent {
        NameComponent::Bytes(b)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extension {
    pub oid: ObjectIdentifier,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl DerWrite for Extension {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.oid.write(writer.next());
            if self.critical {
                true.write(writer.next());
            }
            self.value.write(writer.next());
        });
    }
}

impl BERDecodable for Extension {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;
            let critical = seq_reader.read_default(false, |r| bool::decode_ber(r))?;
            let value = seq_reader.next().read_bytes()?;
            Ok(Extension { oid, critical, value })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Attribute<'a> {
    pub oid: ObjectIdentifier,
    pub value: Vec<DerSequence<'a>>,
}

impl<'a> DerWrite for Attribute<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.oid.write(writer.next());
            writer.next().write_set(|writer| {
                for value in &self.value {
                    value.write(writer.next());
                }
            });
        });
    }
}

impl BERDecodable for Attribute<'static> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;

            let mut value = Vec::<DerSequence<'static>>::new();
            seq_reader.next().read_set_of(|r| {
                value.push(DerSequence::decode_ber(r)?);
                Ok(())
            })?;

            Ok(Attribute { oid, value })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8, // timezone: UTC
}

impl DerWrite for DateTime {
    fn write(&self, writer: DERWriter) {
        let offset = match self.year {
            1950..=1999 => 1900,
            2000..=2049 => 2000,
            _ => 0,
        };
        if offset != 0 {
            let t = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z",
                            self.year - offset,
                            self.month,
                            self.day,
                            self.hour,
                            self.minute,
                            self.second);
            writer.write_tagged_implicit(TAG_UTCTIME, |w| t.as_bytes().write(w));
        } else {
            let t = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z",
                            self.year,
                            self.month,
                            self.day,
                            self.hour,
                            self.minute,
                            self.second);
            writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |w| t.as_bytes().write(w));
        }
    }
}

impl BERDecodable for DateTime {
    /// This code only accepts dates including seconds and in UTC "Z" time zone.
    /// These restrictions are imposed by RFC5280.
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        let tv = reader.read_tagged_der()?;
        let tag = tv.tag();
        let value = tv.value();
        let (year, rest, tz) = match tag {
            TAG_UTCTIME => {
                let (date, tz) = value.split_at(12);
                let (year, rest) = date.split_at(2);

                let year = str::from_utf8(&year).ok().and_then(|s| u16::from_str_radix(s, 10).ok())
                    .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let year = if year < 50 { 2000 + year } else { 1900 + year };

                (year, rest, tz)
            }
            TAG_GENERALIZEDTIME => {
                let (date, tz) = value.split_at(14);
                let (year, rest) = date.split_at(4);

                let year = str::from_utf8(&year).ok().and_then(|s| u16::from_str_radix(s, 10).ok())
                    .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;

                (year, rest, tz)
            }
            _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        };

        if tz != b"Z" {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }

        let mut iter = rest.chunks(2).filter_map(|v| {
            str::from_utf8(&v).ok().and_then(|s| u8::from_str_radix(s, 10).ok())
        });

        let month = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let day = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let hour = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let minute = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let second = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;

        Ok(DateTime { year, month, day, hour, minute, second })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DerSequence<'a> {
    pub value: Cow<'a, [u8]>,
}

impl<'a> DerWrite for DerSequence<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_der(&self.value)
    }
}

impl<'a> From<&'a [u8]> for DerSequence<'a> {
    fn from(b: &'a [u8]) -> DerSequence<'a> {
        DerSequence { value: Cow::Borrowed(b) }
    }
}

impl From<Vec<u8>> for DerSequence<'static> {
    fn from(b: Vec<u8>) -> DerSequence<'static> {
        DerSequence { value: Cow::Owned(b) }
    }
}

impl<'a> AsRef<[u8]> for DerSequence<'a> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl BERDecodable for DerSequence<'static> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        Ok(reader.read_der()?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serialize::DerWrite;
    use yasna;
    use yasna::tags::TAG_UTF8STRING;

    #[test]
    fn name() {
        let name = Name {
            value: vec![
                (oid::commonName.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())),
                (oid::description.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test description".to_vec())),
            ]
        };

        let der = vec![0x30, 0x2f, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09,
                       0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x19, 0x30, 0x17,
                       0x06, 0x03, 0x55, 0x04, 0x0d, 0x0c, 0x10, 0x54, 0x65, 0x73, 0x74, 0x20, 0x64,
                       0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e];

        assert_eq!(yasna::construct_der(|w| name.write(w)), der);
        assert_eq!(yasna::parse_der(&der, |r| Name::decode_ber(r)).unwrap(), name);
    }

    #[test]
    fn name_format() {
        let name = Name {
            value: vec![
                (oid::commonName.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())),
                (ObjectIdentifier::new(vec![1,2,3,4]),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Custom DN".to_vec())),
                (ObjectIdentifier::new(vec![2, 5, 4, 34]),
                 TaggedDerValue::from_tag_and_bytes(TAG_NUMERICSTRING, b"23".to_vec())),
            ]
        };

        assert_eq!(format!("{}", name), "CN=Test name, 1.2.3.4=Custom DN, seeAlso=23");
    }

    #[test]
    fn name_multi_value_rdn() {
        let ber = b"0\x82\x01\xca1\x82\x01]0\x1c\x06\x03U\x04\x0b\x13\x15opc-certtype:instance0r\x06\x03U\x04\x0b\x13kopc-instance:ocid1.instance.oc1.eu-frankfurt-1.abtheljrfsguhltfu6r2y6gwhthevlmgl2ijdl4ozpm34ejr6vgalufakjzq0f\x06\x03U\x04\x0b\x13_opc-compartment:ocid1.tenancy.oc1..aaaaaaaafruudnficveu7ajrk346ilmbdwjzumqe6zn7uoap77awgnpnjoea0a\x06\x03U\x04\x0b\x13Zopc-tenant:ocid1.tenancy.oc1..aaaaaaaafruudnficveu7ajrk346ilmbdwjzumqe6zn7uoap77awgnpnjoea1g0e\x06\x03U\x04\x03\x13^ocid1.instance.oc1.eu-frankfurt-1.abtheljrfsguhltfu6r2y6gwhthevlmgl2ijdl4ozpm34ejr6vgalufakjzq";

        let parsed = yasna::parse_ber(&ber[..], |r| Name::decode_ber(r)).unwrap();
        assert_eq!(parsed.value.len(), 5);
    }

    #[test]
    fn attribute() {
        let attr = Attribute {
            oid: oid::extensionRequest.clone(),
            value: vec![
                b"\x04\x06Hello!".to_vec().into(),
                b"\x04\x06Hello!".to_vec().into(),
            ],
        };

        let der = vec![0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
                       0x31, 0x10, 0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x04, 0x06, 0x48,
                       0x65, 0x6c, 0x6c, 0x6f, 0x21];

        assert_eq!(yasna::construct_der(|w| attr.write(w)), der);
        assert_eq!(yasna::parse_der(&der, |r| Attribute::decode_ber(r)).unwrap(), attr);
    }

    #[test]
    fn datetime() {
        let datetime = DateTime {
            year: 2017,
            month: 5,
            day: 19,
            hour: 12,
            minute: 34,
            second: 56,
        };

        let der = vec![0x17, 0x0d, 0x31, 0x37, 0x30, 0x35, 0x31, 0x39, 0x31, 0x32, 0x33, 0x34,
                       0x35, 0x36, 0x5a];

        assert_eq!(yasna::construct_der(|w| datetime.write(w)), der);
        assert_eq!(yasna::parse_der(&der, |r| DateTime::decode_ber(r)).unwrap(), datetime);
    }
}
