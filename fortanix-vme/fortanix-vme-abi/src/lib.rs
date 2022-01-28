#![deny(warnings)]
#![no_std]
extern crate alloc;
#[cfg(feature="std")]
extern crate std;

use alloc::string::String;
use core::fmt::{self, Formatter};
use core::marker::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeStructVariant;
use serde::de::{EnumAccess, Error as SerdeError, IgnoredAny, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor};

#[cfg(feature="std")]
use {
    std::io,
    std::net::SocketAddr,
    vsock::Error as VsockError,
};

pub const SERVER_PORT: u32 = 10000;

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub enum Request {
    Connect {
        addr: String,
    },
    Bind {
        /// The address the listen to in the parent VM
        addr: String,
        /// The port the enclave is listening on to receive connections from the parent VM. This
        /// port will also be used to reference the connection
        enclave_port: u32,
    },
    Accept {
        /// The Vsock port the enclave is listening on
        enclave_port: u32,
    },
    Close {
        enclave_port: u32,
    },
    Info {
        enclave_port: u32,
        runner_port: Option<u32>,
    },
}

/// Serializes a `Request` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
impl Serialize for Request {
    fn serialize<__S>(&self, __serializer: __S) -> Result<__S::Ok, __S::Error>
    where
        __S: Serializer,
    {
        match *self {
            Request::Connect { ref addr } => {
                let mut __serde_state = match Serializer::serialize_struct_variant(
                    __serializer,
                    "Request",
                    0u32,
                    "Connect",
                    0 + 1,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(&mut __serde_state, "addr", addr) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                SerializeStructVariant::end(__serde_state)
            }
            Request::Bind {
                ref addr,
                ref enclave_port,
            } => {
                let mut __serde_state = match Serializer::serialize_struct_variant(
                    __serializer,
                    "Request",
                    1u32,
                    "Bind",
                    0 + 1 + 1,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(&mut __serde_state, "addr", addr) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(
                    &mut __serde_state,
                    "enclave_port",
                    enclave_port,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                SerializeStructVariant::end(__serde_state)
            }
            Request::Accept { ref enclave_port } => {
                let mut __serde_state = match Serializer::serialize_struct_variant(
                    __serializer,
                    "Request",
                    2u32,
                    "Accept",
                    0 + 1,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(
                    &mut __serde_state,
                    "enclave_port",
                    enclave_port,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                SerializeStructVariant::end(__serde_state)
            }
            Request::Close { ref enclave_port } => {
                let mut __serde_state = match Serializer::serialize_struct_variant(
                    __serializer,
                    "Request",
                    3u32,
                    "Close",
                    0 + 1,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(
                    &mut __serde_state,
                    "enclave_port",
                    enclave_port,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                SerializeStructVariant::end(__serde_state)
            }
            Request::Info {
                ref enclave_port,
                ref runner_port,
            } => {
                let mut __serde_state = match Serializer::serialize_struct_variant(
                    __serializer,
                    "Request",
                    4u32,
                    "Info",
                    0 + 1 + 1,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(
                    &mut __serde_state,
                    "enclave_port",
                    enclave_port,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                match SerializeStructVariant::serialize_field(
                    &mut __serde_state,
                    "runner_port",
                    runner_port,
                ) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                };
                SerializeStructVariant::end(__serde_state)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addr {
    IPv4 {
        ip: [u8; 4],
        port: u16,
    },
    IPv6 {
        ip: [u8; 16],
        port: u16,
        flowinfo: u32,
        scope_id: u32,
    },
}

/// Serializes an `Addr` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
impl Serialize for Addr {
    fn serialize<__S>(&self, __serializer: __S) -> Result<__S::Ok, __S::Error>
    where
        __S: Serializer,
    {
        match *self {
            Addr::IPv4 { ref ip, ref port } => {
                let mut __serde_state =
                    Serializer::serialize_struct_variant(__serializer, "Addr", 0u32, "IPv4", 2)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "ip", ip)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "port", port)?;
                SerializeStructVariant::end(__serde_state)
            }
            Addr::IPv6 {
                ref ip,
                ref port,
                ref flowinfo,
                ref scope_id,
            } => {
                let mut __serde_state =
                    Serializer::serialize_struct_variant(__serializer, "Addr", 1u32, "IPv6", 4)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "ip", ip)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "port", port)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "flowinfo", flowinfo)?;
                SerializeStructVariant::serialize_field(&mut __serde_state, "scope_id", scope_id)?;
                SerializeStructVariant::end(__serde_state)
            }
        }
    }
}

/// Deserializes an `Addr` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
impl<'de> Deserialize<'de> for Addr {
    fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
    where
        __D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        enum __Field {
            __field0,
            __field1,
        }
        struct __FieldVisitor;
        impl<'de> Visitor<'de> for __FieldVisitor {
            type Value = __Field;
            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(__formatter, "variant identifier")
            }
            fn visit_u64<__E>(self, __value: u64) -> Result<Self::Value, __E>
            where
                __E: SerdeError,
            {
                match __value {
                    0u64 => Ok(__Field::__field0),
                    1u64 => Ok(__Field::__field1),
                    _ => Err(SerdeError::invalid_value(
                        Unexpected::Unsigned(__value),
                        &"variant index 0 <= i < 2",
                    )),
                }
            }
            fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
            where
                __E: SerdeError,
            {
                match __value {
                    "IPv4" => Ok(__Field::__field0),
                    "IPv6" => Ok(__Field::__field1),
                    _ => Err(SerdeError::unknown_variant(__value, VARIANTS)),
                }
            }
            fn visit_bytes<__E>(self, __value: &[u8]) -> Result<Self::Value, __E>
            where
                __E: SerdeError,
            {
                match __value {
                    b"IPv4" => Ok(__Field::__field0),
                    b"IPv6" => Ok(__Field::__field1),
                    _ => {
                        let __value = &String::from_utf8_lossy(__value);
                        Err(SerdeError::unknown_variant(__value, VARIANTS))
                    }
                }
            }
        }
        impl<'de> Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
            where
                __D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
            }
        }
        struct __Visitor<'de> {
            marker: PhantomData<Addr>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for __Visitor<'de> {
            type Value = Addr;
            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(__formatter, "enum Addr")
            }
            fn visit_enum<__A>(self, __data: __A) -> Result<Self::Value, __A::Error>
            where
                __A: EnumAccess<'de>,
            {
                match match EnumAccess::variant(__data) {
                    Ok(__val) => __val,
                    Err(__err) => {
                        return Err(__err);
                    }
                } {
                    (__Field::__field0, __variant) => {
                        #[allow(non_camel_case_types)]
                        enum __Field {
                            __field0,
                            __field1,
                            __ignore,
                        }
                        struct __FieldVisitor;
                        impl<'de> Visitor<'de> for __FieldVisitor {
                            type Value = __Field;
                            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(__formatter, "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    0u64 => Ok(__Field::__field0),
                                    1u64 => Ok(__Field::__field1),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    "ip" => Ok(__Field::__field0),
                                    "port" => Ok(__Field::__field1),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8]) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    b"ip" => Ok(__Field::__field0),
                                    b"port" => Ok(__Field::__field1),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
                            where
                                __D: Deserializer<'de>,
                            {
                                Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for __Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(__formatter, "struct variant Addr::IPv4")
                            }
                            #[inline]
                            fn visit_seq<__A>(
                                self,
                                mut __seq: __A,
                            ) -> Result<Self::Value, __A::Error>
                            where
                                __A: SeqAccess<'de>,
                            {
                                let __field0 =
                                    match match SeqAccess::next_element::<[u8; 4]>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                0usize,
                                                &"struct variant Addr::IPv4 with 2 elements",
                                            ));
                                        }
                                    };
                                let __field1 =
                                    match match SeqAccess::next_element::<u16>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                1usize,
                                                &"struct variant Addr::IPv4 with 2 elements",
                                            ));
                                        }
                                    };
                                Ok(Addr::IPv4 {
                                    ip: __field0,
                                    port: __field1,
                                })
                            }
                            #[inline]
                            fn visit_map<__A>(
                                self,
                                mut __map: __A,
                            ) -> Result<Self::Value, __A::Error>
                            where
                                __A: MapAccess<'de>,
                            {
                                let mut __field0: Option<[u8; 4]> = None;
                                let mut __field1: Option<u16> = None;
                                while let Some(__key) =
                                    match MapAccess::next_key::<__Field>(&mut __map) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    }
                                {
                                    match __key {
                                        __Field::__field0 => {
                                            if Option::is_some(&__field0) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "ip",
                                                    ),
                                                );
                                            }
                                            __field0 = Some(
                                                match MapAccess::next_value::<[u8; 4]>(&mut __map) {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        __Field::__field1 => {
                                            if Option::is_some(&__field1) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "port",
                                                    ),
                                                );
                                            }
                                            __field1 = Some(
                                                match MapAccess::next_value::<u16>(&mut __map) {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        _ => {
                                            let _ = match MapAccess::next_value::<IgnoredAny>(
                                                &mut __map,
                                            ) {
                                                Ok(__val) => __val,
                                                Err(__err) => {
                                                    return Err(__err);
                                                }
                                            };
                                        }
                                    }
                                }
                                let __field0 = match __field0 {
                                    Some(__field0) => __field0,
                                    None => /*match de::missing_field("ip") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    }*/
                                        return Err(SerdeError::missing_field("ip")),
                                };
                                let __field1 = match __field1 {
                                    Some(__field1) => __field1,
                                    None => /*match de::missing_field("port") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    },*/

                                        return Err(SerdeError::missing_field("port")),
                                };
                                Ok(Addr::IPv4 {
                                    ip: __field0,
                                    port: __field1,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["ip", "port"];
                        VariantAccess::struct_variant(
                            __variant,
                            FIELDS,
                            __Visitor {
                                marker: PhantomData::<Addr>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (__Field::__field1, __variant) => {
                        #[allow(non_camel_case_types)]
                        enum __Field {
                            __field0,
                            __field1,
                            __field2,
                            __field3,
                            __ignore,
                        }
                        struct __FieldVisitor;
                        impl<'de> Visitor<'de> for __FieldVisitor {
                            type Value = __Field;
                            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(__formatter, "field identifier")
                            }
                            fn visit_u64<__E>(self, __value: u64) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    0u64 => Ok(__Field::__field0),
                                    1u64 => Ok(__Field::__field1),
                                    2u64 => Ok(__Field::__field2),
                                    3u64 => Ok(__Field::__field3),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                            fn visit_str<__E>(self, __value: &str) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    "ip" => Ok(__Field::__field0),
                                    "port" => Ok(__Field::__field1),
                                    "flowinfo" => Ok(__Field::__field2),
                                    "scope_id" => Ok(__Field::__field3),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                            fn visit_bytes<__E>(self, __value: &[u8]) -> Result<Self::Value, __E>
                            where
                                __E: SerdeError,
                            {
                                match __value {
                                    b"ip" => Ok(__Field::__field0),
                                    b"port" => Ok(__Field::__field1),
                                    b"flowinfo" => Ok(__Field::__field2),
                                    b"scope_id" => Ok(__Field::__field3),
                                    _ => Ok(__Field::__ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for __Field {
                            #[inline]
                            fn deserialize<__D>(__deserializer: __D) -> Result<Self, __D::Error>
                            where
                                __D: Deserializer<'de>,
                            {
                                Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                            }
                        }
                        struct __Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for __Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(__formatter, "struct variant Addr::IPv6")
                            }
                            #[inline]
                            fn visit_seq<__A>(
                                self,
                                mut __seq: __A,
                            ) -> Result<Self::Value, __A::Error>
                            where
                                __A: SeqAccess<'de>,
                            {
                                let __field0 =
                                    match match SeqAccess::next_element::<[u8; 16]>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                0usize,
                                                &"struct variant Addr::IPv6 with 4 elements",
                                            ));
                                        }
                                    };
                                let __field1 =
                                    match match SeqAccess::next_element::<u16>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                1usize,
                                                &"struct variant Addr::IPv6 with 4 elements",
                                            ));
                                        }
                                    };
                                let __field2 =
                                    match match SeqAccess::next_element::<u32>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                2usize,
                                                &"struct variant Addr::IPv6 with 4 elements",
                                            ));
                                        }
                                    };
                                let __field3 =
                                    match match SeqAccess::next_element::<u32>(&mut __seq) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    } {
                                        Some(__value) => __value,
                                        None => {
                                            return Err(SerdeError::invalid_length(
                                                3usize,
                                                &"struct variant Addr::IPv6 with 4 elements",
                                            ));
                                        }
                                    };
                                Ok(Addr::IPv6 {
                                    ip: __field0,
                                    port: __field1,
                                    flowinfo: __field2,
                                    scope_id: __field3,
                                })
                            }
                            #[inline]
                            fn visit_map<__A>(
                                self,
                                mut __map: __A,
                            ) -> Result<Self::Value, __A::Error>
                            where
                                __A: MapAccess<'de>,
                            {
                                let mut __field0: Option<[u8; 16]> = None;
                                let mut __field1: Option<u16> = None;
                                let mut __field2: Option<u32> = None;
                                let mut __field3: Option<u32> = None;
                                while let Some(__key) =
                                    match MapAccess::next_key::<__Field>(&mut __map) {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    }
                                {
                                    match __key {
                                        __Field::__field0 => {
                                            if Option::is_some(&__field0) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "ip",
                                                    ),
                                                );
                                            }
                                            __field0 = Some(
                                                match MapAccess::next_value::<[u8; 16]>(&mut __map)
                                                {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        __Field::__field1 => {
                                            if Option::is_some(&__field1) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "port",
                                                    ),
                                                );
                                            }
                                            __field1 = Some(
                                                match MapAccess::next_value::<u16>(&mut __map) {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        __Field::__field2 => {
                                            if Option::is_some(&__field2) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "flowinfo",
                                                    ),
                                                );
                                            }
                                            __field2 = Some(
                                                match MapAccess::next_value::<u32>(&mut __map) {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        __Field::__field3 => {
                                            if Option::is_some(&__field3) {
                                                return Err(
                                                    <__A::Error as SerdeError>::duplicate_field(
                                                        "scope_id",
                                                    ),
                                                );
                                            }
                                            __field3 = Some(
                                                match MapAccess::next_value::<u32>(&mut __map) {
                                                    Ok(__val) => __val,
                                                    Err(__err) => {
                                                        return Err(__err);
                                                    }
                                                },
                                            );
                                        }
                                        _ => {
                                            let _ = match MapAccess::next_value::<IgnoredAny>(
                                                &mut __map,
                                            ) {
                                                Ok(__val) => __val,
                                                Err(__err) => {
                                                    return Err(__err);
                                                }
                                            };
                                        }
                                    }
                                }
                                let __field0 = match __field0 {
                                    Some(__field0) => __field0,
                                    None => /*match de::missing_field("ip") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    },*/

                                    return Err(SerdeError::missing_field("ip")),
                                };
                                let __field1 = match __field1 {
                                    Some(__field1) => __field1,
                                    None => /*match de::missing_field("port") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    },*/

                                        return Err(SerdeError::missing_field("port")),
                                };
                                let __field2 = match __field2 {
                                    Some(__field2) => __field2,
                                    None => /*match de::missing_field("flowinfo") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    },*/
                                        return Err(SerdeError::missing_field("flowinfo")),
                                };
                                let __field3 = match __field3 {
                                    Some(__field3) => __field3,
                                    None => /*match de::missing_field("scope_id") {
                                        Ok(__val) => __val,
                                        Err(__err) => {
                                            return Err(__err);
                                        }
                                    },*/

                                        return Err(SerdeError::missing_field("scop_id")),
                                };
                                Ok(Addr::IPv6 {
                                    ip: __field0,
                                    port: __field1,
                                    flowinfo: __field2,
                                    scope_id: __field3,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["ip", "port", "flowinfo", "scope_id"];
                        VariantAccess::struct_variant(
                            __variant,
                            FIELDS,
                            __Visitor {
                                marker: PhantomData::<Addr>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                }
            }
        }
        const VARIANTS: &'static [&'static str] = &["IPv4", "IPv6"];
        Deserializer::deserialize_enum(
            __deserializer,
            "Addr",
            VARIANTS,
            __Visitor {
                marker: PhantomData::<Addr>,
                lifetime: PhantomData,
            },
        )
    }
}

#[cfg(feature="std")]
impl From<SocketAddr> for Addr {
    fn from(addr: SocketAddr) -> Addr {
        match addr {
            SocketAddr::V4(addr) => {
                Addr::IPv4 {
                    ip: addr.ip().octets(),
                    port: addr.port(),
                }
            },
            SocketAddr::V6(addr) => {
                Addr::IPv6 {
                    ip: addr.ip().octets(),
                    port: addr.port(),
                    flowinfo: addr.flowinfo(),
                    scope_id: addr.scope_id(),
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Connected {
        /// The vsock port the proxy is listening on for an incoming connection
        proxy_port: u32,
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
    },
    Bound {
        /// The local TCP address the parent VM is listening on
        local: Addr,
    },
    IncomingConnection {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party
        peer: Addr,
        /// The vsock port number the runner will connect to the enclave in order to forward the
        /// incoming connection
        proxy_port: u32,
    },
    Closed,
    Info {
        /// The local address (as used by the runner)
        local: Addr,
        /// The address of the remote party for open connection, None for server sockets
        peer: Option<Addr>,
    },
    Failed(Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    ConnectionNotFound,
    SystemError(i32),
    Unknown,
    VsockError,
}

/// Serializes an `Error` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Error::ConnectionNotFound => {
                Serializer::serialize_unit_variant(serializer, "Error", 0u32, "ConnectionNotFound")
            }
            Error::SystemError(ref errno) => Serializer::serialize_newtype_variant(
                serializer,
                "Error",
                1u32,
                "SystemError",
                errno,
            ),
            Error::Unknown => {
                Serializer::serialize_unit_variant(serializer, "Error", 2u32, "Unknown")
            }
            Error::VsockError => {
                Serializer::serialize_unit_variant(serializer, "Error", 3u32, "VsockError")
            }
        }
    }
}

/// Deserializes an `Error` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        enum __Field {
            __field0,
            __field1,
            __field2,
            __field3,
        }
        struct __FieldVisitor;
        impl<'de> Visitor<'de> for __FieldVisitor {
            type Value = __Field;
            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(__formatter, "variant identifier")
            }
            fn visit_u64<E>(self, __value: u64) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match __value {
                    0u64 => Ok(__Field::__field0),
                    1u64 => Ok(__Field::__field1),
                    2u64 => Ok(__Field::__field2),
                    3u64 => Ok(__Field::__field3),
                    _ => Err(SerdeError::invalid_value(
                        Unexpected::Unsigned(__value),
                        &"variant index 0 <= i < 4",
                    )),
                }
            }
            fn visit_str<E>(self, __value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match __value {
                    "ConnectionNotFound" => Ok(__Field::__field0),
                    "SystemError" => Ok(__Field::__field1),
                    "Unknown" => Ok(__Field::__field2),
                    "VsockError" => Ok(__Field::__field3),
                    _ => Err(SerdeError::unknown_variant(__value, VARIANTS)),
                }
            }
            fn visit_bytes<E>(self, __value: &[u8]) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match __value {
                    b"ConnectionNotFound" => Ok(__Field::__field0),
                    b"SystemError" => Ok(__Field::__field1),
                    b"Unknown" => Ok(__Field::__field2),
                    b"VsockError" => Ok(__Field::__field3),
                    _ => {
                        let __value = &String::from_utf8_lossy(__value);
                        Err(SerdeError::unknown_variant(__value, VARIANTS))
                    }
                }
            }
        }
        impl<'de> Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(deserializer, __FieldVisitor)
            }
        }
        struct ErrorVisitor<'de> {
            marker: PhantomData<Error>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for ErrorVisitor<'de> {
            type Value = Error;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(formatter, "enum Error")
            }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match EnumAccess::variant(data)? {
                    (__Field::__field0, __variant) => {
                        match VariantAccess::unit_variant(__variant) {
                            Ok(__val) => __val,
                            Err(__err) => {
                                return Err(__err);
                            }
                        };
                        Ok(Error::ConnectionNotFound)
                    }
                    (__Field::__field1, __variant) => Result::map(
                        VariantAccess::newtype_variant::<i32>(__variant),
                        Error::SystemError,
                    ),
                    (__Field::__field2, __variant) => {
                        match VariantAccess::unit_variant(__variant) {
                            Ok(__val) => __val,
                            Err(__err) => {
                                return Err(__err);
                            }
                        };
                        Ok(Error::Unknown)
                    }
                    (__Field::__field3, __variant) => {
                        match VariantAccess::unit_variant(__variant) {
                            Ok(__val) => __val,
                            Err(__err) => {
                                return Err(__err);
                            }
                        };
                        Ok(Error::VsockError)
                    }
                }
            }
        }
        const VARIANTS: &'static [&'static str] =
            &["ConnectionNotFound", "SystemError", "Unknown", "VsockError"];
        Deserializer::deserialize_enum(
            deserializer,
            "Error",
            VARIANTS,
            ErrorVisitor {
                marker: PhantomData::<Error>,
                lifetime: PhantomData,
            },
        )
    }
}

#[cfg(feature="std")]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        if let Some(errno) = error.raw_os_error() {
            Error::SystemError(errno)
        } else {
            Error::Unknown
        }
    }
}

#[cfg(feature="std")]
impl From<VsockError> for Error {
    fn from(error: VsockError) -> Error {
        match error {
            VsockError::EntropyError        => Error::VsockError,
            VsockError::SystemError(errno)  => Error::SystemError(errno),
            VsockError::WrongAddressType    => Error::VsockError,
            VsockError::ZeroDurationTimeout => Error::VsockError,
            VsockError::ReservedPort        => Error::VsockError,
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::string::String;
    use std::vec::Vec;
    use crate::{Addr, Error, Request};

    #[test]
    fn test_addr() {
        let sock_addr = SocketAddr::from_str("10.11.12.13:4567").unwrap();
        if let Addr::IPv4 { port, ip } = sock_addr.into() {
            assert_eq!(IpAddr::from(ip), sock_addr.ip());   
            assert_eq!(port, sock_addr.port());
            assert_eq!(port, 4567);
        } else {
            panic!("Not IPv4")
        }
    }

    #[test]
    fn test_error() {
        let data: Vec<(Error, Vec<u8>)> = Vec::from([
            (Error::ConnectionNotFound, Vec::from([0x72, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
                                                   0x6e, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64])),
            (Error::SystemError(0), Vec::from([0xa1, 0x6b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x45, 0x72,
                                               0x72, 0x6f, 0x72, 0x0])),
            (Error::SystemError(42), Vec::from([0xa1, 0x6b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x45, 0x72,
                                                0x72, 0x6f, 0x72, 0x18, 0x2a])),
            (Error::SystemError(i32::MAX), Vec::from([0xa1, 0x6b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x45, 0x72,
                                                      0x72, 0x6f, 0x72, 0x1a, 0x7f, 0xff, 0xff, 0xff])),
            (Error::Unknown, Vec::from([0x67, 0x55, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e])),
            (Error::VsockError, Vec::from([0x6a, 0x56, 0x73, 0x6f, 0x63, 0x6b, 0x45, 0x72, 0x72, 0x6f, 0x72])),
        ]);

        for (err, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(&err).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Error>(&bin).unwrap(), *err);
        }
    }

    #[test]
    fn test_addr_encoding() {
        let data: Vec<(Addr, Vec<u8>)> = Vec::from([
            (Addr::IPv4{ip: [1, 2, 3, 4], port: 2}, Vec::from([0xa1, 0x64, 0x49, 0x50, 0x76, 0x34, 0xa2, 0x62,
                                                               0x69, 0x70, 0x84, 0x01, 0x02, 0x03, 0x04, 0x64,
                                                               0x70, 0x6f, 0x72, 0x74, 0x02])),
            (Addr::IPv4{ip: [127, 0, 0, 1], port: 3458}, Vec::from([0xa1, 0x64, 0x49, 0x50, 0x76, 0x34, 0xa2,
                                                                    0x62, 0x69, 0x70, 0x84, 0x18, 0x7f, 0x00,
                                                                    0x00, 0x01, 0x64, 0x70, 0x6f, 0x72, 0x74,
                                                                    0x19, 0x0d, 0x82])),
            (Addr::IPv6{ip: [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8], port: 3458, flowinfo: 1, scope_id: 2},
                Vec::from([0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69, 0x70, 0x90, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x64,
                           0x70, 0x6f, 0x72, 0x74, 0x19, 0x0d, 0x82, 0x68, 0x66, 0x6c, 0x6f, 0x77, 0x69, 0x6e,
                           0x66, 0x6f, 0x01, 0x68, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x02])),
            (Addr::IPv6{ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], port: 0, flowinfo: 0, scope_id: 0},
                Vec::from([0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69, 0x70, 0x90, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
                           0x70, 0x6f, 0x72, 0x74, 0x00, 0x68, 0x66, 0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x66, 0x6f,
                           0x00, 0x68, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x0])),
        ]);

        for (addr, bin) in data.iter() {

        std::println!("{:#02x?}", serde_cbor::ser::to_vec(addr).unwrap());
            assert_eq!(serde_cbor::ser::to_vec(&addr).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Addr>(&bin).unwrap(), *addr);
        }
        //std::println!("{:#02x?}", serde_cbor::ser::to_vec(&Addr::IPv6{ip: [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8], port: 3458, flowinfo: 1, scope_id: 2}).unwrap());
        //std::println!("{:#02x?}", serde_cbor::ser::to_vec(&Addr::IPv4{ip: [1, 2, 3, 4], port: 2}).unwrap());
    }

    #[test]
    fn test_request_encoding() {
        let data: Vec<(Request, Vec<u8>)> = Vec::from([
            (
                Request::Connect {
                    addr: String::new(),
                },
                Vec::from([
                    0xa1, 0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0xa1, 0x64, 0x61, 0x64,
                    0x64, 0x72, 0x60,
                ]),
            ),
            (
                Request::Connect {
                    addr: String::from("google.com"),
                },
                Vec::from([
                    0xa1, 0x67, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0xa1, 0x64, 0x61, 0x64,
                    0x64, 0x72, 0x6a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
                ]),
            ),
            (
                Request::Bind {
                    addr: String::new(),
                    enclave_port: 0,
                },
                Vec::from([
                    0xa1, 0x64, 0x42, 0x69, 0x6e, 0x64, 0xa2, 0x64, 0x61, 0x64, 0x64, 0x72, 0x60,
                    0x6c, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74,
                    0x00,
                ]),
            ),
            (
                Request::Bind {
                    addr: String::from("localhost"),
                    enclave_port: 1234,
                },
                Vec::from([
                    0xa1, 0x64, 0x42, 0x69, 0x6e, 0x64, 0xa2, 0x64, 0x61, 0x64, 0x64, 0x72, 0x69,
                    0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x6c, 0x65, 0x6e, 0x63,
                    0x6c, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x19, 0x04, 0xd2,
                ]),
            ),
            (
                Request::Accept { enclave_port: 0 },
                Vec::from([
                    0xa1, 0x66, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0xa1, 0x6c, 0x65, 0x6e, 0x63,
                    0x6c, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00,
                ]),
            ),
            (
                Request::Accept { enclave_port: 80 },
                Vec::from([
                    0xa1, 0x66, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0xa1, 0x6c, 0x65, 0x6e, 0x63,
                    0x6c, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x50,
                ]),
            ),
            (
                Request::Close { enclave_port: 0 },
                Vec::from([
                    0xa1, 0x65, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0xa1, 0x6c, 0x65, 0x6e, 0x63, 0x6c,
                    0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00,
                ]),
            ),
            (
                Request::Close { enclave_port: 80 },
                Vec::from([
                    0xa1, 0x65, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0xa1, 0x6c, 0x65, 0x6e, 0x63, 0x6c,
                    0x61, 0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x50,
                ]),
            ),
            (
                Request::Info {
                    enclave_port: 0,
                    runner_port: None,
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0xa2, 0x6c, 0x65, 0x6e, 0x63, 0x6c, 0x61,
                    0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00, 0x6b, 0x72, 0x75, 0x6e, 0x6e,
                    0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0xf6,
                ]),
            ),
            (
                Request::Info {
                    enclave_port: 0,
                    runner_port: Some(0),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0xa2, 0x6c, 0x65, 0x6e, 0x63, 0x6c, 0x61,
                    0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00, 0x6b, 0x72, 0x75, 0x6e, 0x6e,
                    0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00,
                ]),
            ),
            (
                Request::Info {
                    enclave_port: 1024,
                    runner_port: Some(42),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0xa2, 0x6c, 0x65, 0x6e, 0x63, 0x6c, 0x61,
                    0x76, 0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x19, 0x04, 0x00, 0x6b, 0x72, 0x75,
                    0x6e, 0x6e, 0x65, 0x72, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x2a,
                ]),
            ),
        ]);

        for (req, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(&req).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Request>(&bin).unwrap(), *req);
        }
    }
}
