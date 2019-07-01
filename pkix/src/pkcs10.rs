use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, BERDecodable, Tag};
use {DerWrite, FromDer};
use types::*;
use bit_vec::BitVec;

// RFC2986, 4.1

pub type DerCertificationRequest =
    CertificationRequest<CertificationRequestInfo<'static, DerSequence<'static>>,
                         DerSequence<'static>,
                         BitVec>;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificationRequest<I = CertificationRequestInfo<'static, DerSequence<'static>>,
                                A: SignatureAlgorithm = DerSequence<'static>,
                                S = BitVec> {
    pub reqinfo: I,
    pub sigalg: A,
    pub sig: S,
}

impl<I: DerWrite, A: SignatureAlgorithm + DerWrite, S: DerWrite> DerWrite for CertificationRequest<I, A, S> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.reqinfo.write(writer.next());
            self.sigalg.write(writer.next());
            self.sig.write(writer.next());
        });
    }
}

impl<I: BERDecodable, A: SignatureAlgorithm + BERDecodable, S: BERDecodable> BERDecodable for CertificationRequest<I, A, S> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let reqinfo = I::decode_ber(r.next())?;
            let sigalg = A::decode_ber(r.next())?;
            let sig = S::decode_ber(r.next())?;

            Ok(CertificationRequest { reqinfo, sigalg, sig })
        })
    }
}

impl<'a, K, A: SignatureAlgorithm, S> CertificationRequest<CertificationRequestInfo<'a, K>, A, S> {
    pub fn get_attribute<T: FromDer + HasOid>(&self) -> Option<Vec<T>> {
        let oid = T::oid();

        let mut iter = self.reqinfo.attributes.iter().filter(|a| a.oid == *oid);

        // We reject CSRs where the same attribute (same OID) appears multiple times. Note that
        // this is different from the case where the attribute (OID) appears once and has
        // multiple values, that is handled by the second level of iteration below.
        match (iter.next(), iter.next()) {
            (Some(attr), None) => {
                attr.value
                    .iter()
                    .map(|v| T::from_der(v))
                    .collect::<ASN1Result<Vec<T>>>()
                    .ok()
            }
            _ => None,
        }
    }

    pub fn get_singular_attribute<T: FromDer + HasOid>(&self) -> Option<T> {
        match self.get_attribute() {
            None => None,
            Some(mut values) => {
                if values.len() != 1 {
                    // warn!("Unexpected number of attribute values in CSR");
                    return None;
                } else {
                    Some(values.pop().unwrap())
                }
            }
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificationRequestInfo<'e, K> {
    // version: v1
    pub subject: Name,
    pub spki: K,
    pub attributes: Vec<Attribute<'e>>,
}

const CERTIFICATION_REQUEST_INFO_V1: u8 = 0;

impl<'e, K: DerWrite> DerWrite for CertificationRequestInfo<'e, K> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            CERTIFICATION_REQUEST_INFO_V1.write(writer.next());
            self.subject.write(writer.next());
            self.spki.write(writer.next());
            writer.next().write_tagged_implicit(Tag::context(0), |w| {
                w.write_set(|w| for attr in &self.attributes {
                    attr.write(w.next());
                })
            });
        });
    }
}

impl<K: BERDecodable> BERDecodable for CertificationRequestInfo<'static, K> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let version = r.next().read_u8()?;
            if version != CERTIFICATION_REQUEST_INFO_V1 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
            let subject = Name::decode_ber(r.next())?;
            let spki = K::decode_ber(r.next())?;
            let attributes = r.next().read_tagged_implicit(Tag::context(0), |r| {
                let mut attributes = Vec::<Attribute<'static>>::new();
                r.read_set_of(|r| {
                    attributes.push(Attribute::decode_ber(r)?);
                    Ok(())
                })?;
                Ok(attributes)
            })?;

            Ok(CertificationRequestInfo { subject, spki, attributes })
        })
    }
}
