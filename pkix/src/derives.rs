use std::hash::Hash;
pub use {DerWrite, FromBer, ToDer};
pub use yasna::models::ObjectIdentifier;
pub use yasna::{
    construct_der, ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, BERReaderSeq, DERWriter,
    DERWriterSeq, BERDecodable, Tag,
};

// Provides callbacks to the main sequence's read and write functions.
pub trait SubSequenceFromBER: Sized + Eq + Hash {
    fn decode_ber<'a, 'b>(reader: &mut BERReaderSeq<'a, 'b>) -> ASN1Result<Self>;
}

pub trait SubSequenceDerWrite {
    fn write(&self, writer: &mut DERWriterSeq);
}

#[macro_export]
macro_rules! enum_oid {
    ($name:ident {
        $($variant:ident = $val:expr),*,
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[allow(non_camel_case_types)]
        pub enum $name {
            $($variant),*
        }

        // TryFrom is not stable!
        impl $name {
            #[allow(unused)]
            fn try_from_oid(oid: ObjectIdentifier) -> Result<Self, ASN1Error> {
                $(if oid == *$val {
                      return Ok($name::$variant);
                  }
                 )*
                 return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
        }

        // HasOid servers similar purpose,
        // but it does not fit into `match and return OID`.
        impl <'a>From<&'a $name> for &'static ObjectIdentifier {
            fn from(item : &'a $name) -> &'static ObjectIdentifier {
                match item {
                    $(&$name::$variant => &$val),*
                }
            }
        }

        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                writer.write_oid(self.into())
            }
        }

        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_oid().and_then(|oid| {$name::try_from_oid(oid)})
            }
        }
    }
}

#[macro_export]
macro_rules! define_content_with_associated_type {
    ($name:ident => $Ty:ident {
        $($variant:ident),*,
    }) => {
        define_content_with_associated_type! {
            $name => $Ty {
                $($variant = $variant),*,
            }
        }
    };

    ($name:ident => $Ty:ident {
        $($variant:ident = $typeVariant:ident),*,
    }) => {
        define_content_with_associated_type! {
            $name => $Ty {
                $($variant($variant) = $variant),*,
            }
        }
        $(impl From<$variant> for $name {
            fn from(var : $variant) -> $name {
                $name::$variant{0: var}
            }
        })*
    };
    ($name:ident => $Ty:ident {
        $($variant:ident($innerVariant:ty) = $typeVariant:ident),*,
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[allow(non_camel_case_types, non_snake_case)]
        pub enum $name {
            $($variant($innerVariant)),*
        }
        impl $name {
            pub fn get_type(&self) -> $Ty {
                match self  {
                    $(&$name::$variant(_) => $Ty::$typeVariant),*
                }
            }
        }
    }
}

/// content_with_associated_type helps us define enums where the `type`
/// of the variant could be another enumerated type, like a subset of oids
/// or say a CMS version etc.
///
/// This macro would define such a content given all the variants as input, and,
/// implement get_type, content_reader and content_writer for the variants.
/// With the above three it is easy to implement a reader or writer for the enum type.
///
/// In most of the cases of CMS spec the actual payload in such cases is a sequence,
/// So if the enum name is followed by Sequence, the reader and writer for the enum are
/// implemented too. There are two kinds of such sequences in the spec, one where the type
/// is embedded at the beginning of the sequence (CMSVersion) and other where the types is encoded
/// followed by the sequence (ContentInfo).

#[macro_export]
macro_rules! impl_content_with_associated_type {

    ($name:ident : Sequence TypeEmbedded => $Ty:ident {
         $($tail:tt)*
    }) => {
        impl_content_with_associated_type! {
            $name => $Ty SubSequenceDerWrite, SubSequenceFromBER, &mut BERReaderSeq {
                $($tail)*
            }
        }
        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                writer.write_sequence(|writer| {
                    self.get_type().write(writer.next());
                    self.content_writer().write(writer);
                })
             }
        }

        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_sequence(|seq_reader| {
                    let content_type = <$Ty as BERDecodable>::decode_ber(seq_reader.next())?;
                    $name::content_reader(content_type, seq_reader)
                })
            }
        }
    };
    ($name:ident : Sequence => $Ty:ident {
         $($tail:tt)*
    }) => {
        impl_content_with_associated_type!($name => $Ty {
                   $($tail)*
        });
        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                writer.write_sequence(|writer| {
                    self.get_type().write(writer.next());
                    self.content_writer().write(writer.next());
                })
             }
        }

        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_sequence(|seq_reader| {
                    let content_type = <$Ty as BERDecodable>::decode_ber(seq_reader.next())?;
                    $name::content_reader(content_type, seq_reader.next())
                })
            }
        }
    };
    ($name:ident => $Ty:ident {
        $($tail:tt)*
    }) => {
        impl_content_with_associated_type! {
            $name => $Ty DerWrite,BERDecodable,BERReader {
                $($tail)*
            }
        }
    };

    ($name:ident => $Ty:ident $writeTrait:ident, $readTrait:ident, $readerType:ty {
        $($variant:ident),*,
    }) => {
        impl_content_with_associated_type! {
            $name => $Ty $writeTrait, $readTrait, $readerType {
                $($variant = $variant),*,
            }
        }
    };
    ($name:ident => $Ty:ident  $writeTrait:ident, $readTrait:ident,$readerType:ty {
        $($variant:ident($innerVariant:ty)),*,
    }) => {
        impl_content_with_associated_type! {
            $name => $Ty $writeTrait, $readTrait, $readerType {
                $($variant($innerVariant) = $variant),*,
            }
        }
    };
    ($name:ident => $Ty:ident $writeTrait:ident, $readTrait:ident,$readerType:ty {
        $($variant:ident = $typeVariant:ident),*,
    }) => {
        impl_content_with_associated_type! {
            $name => $Ty $writeTrait, $readTrait, $readerType {
                $($variant($variant) = $typeVariant),*,
            }
        }
        $(impl From<$variant> for $name {
            fn from(var : $variant) -> $name {
                $name::$variant{0: var}
            }
        })*
    };
    ($name:ident => $Ty:ident  $writeTrait:ident, $readTrait:ident,$readerType:ty {
        $($variant:ident($innerVariant:ty) = $typeVariant:ident),*,
    }) => {
        define_content_with_associated_type! {
            $name => $Ty {
                $($variant($innerVariant) = $typeVariant),*,
            }
        }
        impl $name {
            fn content_writer<'a>(&'a self) -> Box<&'a dyn $writeTrait> {
                match self  {
                    $(&$name::$variant(ref var) => Box::new(var)),*
                }
            }
            fn content_reader(content_type: $Ty, reader : $readerType)-> ASN1Result<Self> {
                #[allow(unreachable_patterns)]
                match content_type {
                    $($Ty::$typeVariant => <$innerVariant as $readTrait>::decode_ber(reader).and_then(|v| Ok($name::$variant(v)))),*,
                    _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                }
            }
        }
    }
}

// Subtype For an enums with associated data
#[macro_export]
macro_rules! enum_subtype {
    ($name:ident => $super:ident {
        $($variant:ident),*,
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[allow(non_camel_case_types)]
        pub enum $name {
            $($variant($variant)),*
        }

        // TryFrom is not stable!
        impl $name {
            #[allow(unused)]
            pub fn try_from_super(sup: $super) -> Result<Self, ASN1Error> {
                match sup {
                    $($super::$variant(var) => Ok($name::$variant{0: var}))*,
                    _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                }
            }
        }

        $(
            impl From<$variant> for $name {
                fn from(item : $variant) -> $name {
                    $name::$variant{0: item}
                }
            }
        )*

        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                match self {
                    // TODO cow might avoid clone
                    $(&$name::$variant{0: ref var} => {
                                            $super::$variant{0: var.clone()}.write(writer);
                                          }
                    ),*
                }
            }
        }

        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                <$super as BERDecodable>::decode_ber(reader).and_then(|s| $name::try_from_super(s))

            }
        }
    }
}

#[macro_export]
macro_rules! derive_set {
    ($elem_name:ty => $set_name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash, Default)]
        #[allow(non_camel_case_types, non_snake_case)]
        pub struct $set_name {
            elements: Vec<$elem_name>,
        }
        impl DerWrite for $set_name {
            fn write(&self, writer: DERWriter) {
                writer.write_set(|w| {
                    for element in &self.elements {
                        element.write(w.next());
                    }
                })
            }
        }

        impl BERDecodable for $set_name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                let mut elements = Vec::<$elem_name>::new();
                // While reading from BER, set_of and set are unordered.
                // If we were to read from DER instead, we would have different
                // ordering rules for set and set_of.
                reader.read_set_of(|r| {
                    let info = <$elem_name as BERDecodable>::decode_ber(r)?;
                    elements.push(info);
                    Ok(())
                })?;
                Ok($set_name { elements })
            }
        }
        impl From<Vec<$elem_name>> for $set_name {
            fn from(elements: Vec<$elem_name>) -> $set_name {
                $set_name { elements }
            }
        }
        impl $set_name {
            #[allow(unused)]
            pub fn push<T: Into<$elem_name>>(&mut self, elem: T) {
                self.elements.push(elem.into());
            }
        }
        impl From<$set_name> for Vec<$elem_name> {
            fn from(set_name : $set_name) -> Vec<$elem_name> {
                set_name.elements
            }
        }
    };
}

#[macro_export]
macro_rules! derive_set_of {
    ($elem_name:ty => $set_name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash, Default)]
        #[allow(non_camel_case_types, non_snake_case)]
        pub struct $set_name {
            elements: Vec<$elem_name>,
        }
        impl DerWrite for $set_name {
            fn write(&self, writer: DERWriter) {
                writer.write_set_of(|w| {
                    for element in &self.elements {
                        element.write(w.next());
                    }
                })
            }
        }

        impl BERDecodable for $set_name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                let mut elements = Vec::<$elem_name>::new();
                reader.read_set_of(|r| {
                    let info = <$elem_name as BERDecodable>::decode_ber(r)?;
                    elements.push(info);
                    Ok(())
                })?;
                Ok($set_name { elements })
            }
        }
        impl From<Vec<$elem_name>> for $set_name {
            fn from(elements: Vec<$elem_name>) -> $set_name {
                $set_name { elements }
            }
        }
        impl $set_name {
            #[allow(unused)]
            pub fn push<T: Into<$elem_name>>(&mut self, elem: T) {
                self.elements.push(elem.into());
            }
        }
        impl From<$set_name> for Vec<$elem_name> {
            fn from(set_name : $set_name) -> Vec<$elem_name> {
                set_name.elements
            }
        }
    };
}

#[macro_export]
macro_rules! derive_sequence {
    ($name:ident {
         $($item:ident : [$tag:tt] $tag_type:ident : $item_type:ty),*$(,)*
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[allow(non_camel_case_types, non_snake_case)]
         pub struct $name {
                $(pub $item : $item_type),*,
         }

        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                writer.write_sequence(|writer| {
                    derive_sequence! {
                        $name deriveDerWr(self, writer.next()) {
                             $($item : [$tag] $tag_type  : $item_type),*,
                        }
                    }
                })
             }
        }
        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_sequence(|reader| {
                    derive_sequence! {
                        $name deriveBerRd(reader.next()) {
                             $($item : [$tag] $tag_type : $item_type),*,
                        }
                    }
                    let obj = $name {
                            $($item),*,
                        };
                    Ok(obj)
                })
            }
        }
    };
    ($name:ident {
         $($item:ident : $item_type:ty),*$(,)*
    }) => {
          derive_sequence! {
              $name {
                  $($item : [_] UNTAGGED : $item_type),*,
              }
          }
    };

    ($name:ident : Subsequence {
         $($item:ident : [$tag:tt] $tag_type:ident : $item_type:ty),*$(,)*
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        #[allow(non_camel_case_types, non_snake_case)]
         pub struct $name {
                $(pub $item : $item_type),*,
         }

        impl SubSequenceDerWrite for $name {
           fn write(&self, writer: &mut DERWriterSeq) {
                    derive_sequence! {
                        $name deriveDerWr(self, writer.next()) {
                             $($item : [$tag] $tag_type  : $item_type),*,
                        }
                    }
           }
        }
        impl SubSequenceFromBER for $name {
           fn decode_ber<'a, 'b>(reader: &mut BERReaderSeq<'a, 'b>) -> ASN1Result<Self> {
                    derive_sequence! {
                        $name deriveBerRd(reader.next()) {
                             $($item : [$tag] $tag_type : $item_type),*,
                        }
                    }
                    let obj = $name {
                            $($item),*,
                        };
                    Ok(obj)
           }
        }
    };
    ($name:ident : Subsequence {
         $($item:ident : $item_type:ty),*$(,)*
    }) => {
          derive_sequence! {
              $name :Subsequence {
                  $($item : [_] UNTAGGED : $item_type),*,
              }
          }
    };


    ($name:ident deriveDerWr($written:ident, $writer:expr) { }) => {};
    ($name:ident deriveDerWr($written:ident, $writer:expr) {
          $item:ident : [$tag:tt] EXPLICIT : $item_type:ty,
          $($tail:tt)*
    }) => {
                $writer.write_tagged(Tag::context($tag), |writer| {
                     $written.$item.write(writer)
                });
                derive_sequence! {
                    $name deriveDerWr($written, $writer) {
                         $($tail)*
                    }
                }
    };
    ($name:ident deriveDerWr($written:ident, $writer:expr) {
          $item:ident : [$tag:tt] IMPLICIT : $item_type:ty,
          $($tail:tt)*
    }) => {
                $writer.write_tagged_implicit(Tag::context($tag), |writer| {
                     $written.$item.write(writer)
                });
                derive_sequence! {
                    $name deriveDerWr($written, $writer) {
                         $($tail)*
                    }
                }
    };
    ($name:ident deriveDerWr($written:ident, $writer:expr) {
          $item:ident : [$tag:tt] UNTAGGED : $item_type:ty,
          $($tail:tt)*
    }) => {
        $written.$item.write($writer);
        derive_sequence! {
            $name deriveDerWr($written, $writer) {
                $($tail)*
            }
        }
    };

    ($name:ident deriveBerRd($reader:expr) { }) => {};
    ($name:ident deriveBerRd($reader:expr) {
          $item:ident : [$tag:tt] EXPLICIT : $item_type:ty,
          $($tail:tt)*
    }) => {

                #[allow(non_camel_case_types, non_snake_case)]
                let $item = $reader.read_tagged(Tag::context($tag), |reader| {
                   <$item_type as BERDecodable>::decode_ber(reader)
                })?;
                derive_sequence! {
                    $name deriveBerRd($reader) {
                         $($tail)*
                    }
                }
    };
    ($name:ident deriveBerRd($reader:expr) {
          $item:ident : [$tag:tt] IMPLICIT : $item_type:ty,
          $($tail:tt)*
    }) => {
              #[allow(non_camel_case_types, non_snake_case)]
              let $item= $reader.read_tagged_implicit(Tag::context($tag), |reader| {
                  <$item_type as BERDecodable>::decode_ber(reader)
              })?;
              derive_sequence! {
                  $name deriveBerRd($reader) {
                      $($tail)*
                  }
               }
    };
    ($name:ident deriveBerRd($reader:expr) {
          $item:ident : [$tag:tt] UNTAGGED : $item_type:ty,
          $($tail:tt)*
    }) => {
               #[allow(non_camel_case_types, non_snake_case)]
               let $item = <$item_type as BERDecodable>::decode_ber($reader)?;
               derive_sequence! {
                   $name deriveBerRd($reader) {
                       $($tail)*
                   }
                }
          }
}

// Helps one define enum to and from u32
// And also derives serializations for the same

#[macro_export]
macro_rules! define_version {
    ($name:ident {
        $($ver:ident = $n:expr),*,
    }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub enum $name {
            $($ver = $n),*,
        }
        impl DerWrite for $name {
            fn write(&self, writer: DERWriter) {
                ((*self).clone() as u32).write(writer)
            }
        }

        impl BERDecodable for $name {
            fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
                reader.read_u32().and_then(|n| {
                    match n {
                        $($n => Ok($name::$ver)),*,
                        _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid))
                    }
                })
            }
        }
    }
}
