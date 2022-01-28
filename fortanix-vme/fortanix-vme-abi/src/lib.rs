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
use serde::de::{EnumAccess, Error as SerdeError, IgnoredAny, MapAccess, VariantAccess, Visitor};

#[cfg(feature="std")]
use {
    std::io,
    std::net::SocketAddr,
    vsock::Error as VsockError,
};

pub const SERVER_PORT: u32 = 10000;

#[derive(Debug, PartialEq, Eq)]
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Request::Connect { ref addr } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 0u32, "Connect", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "addr", addr)?;
                SerializeStructVariant::end(state)
            }
            Request::Bind { ref addr, ref enclave_port } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 1u32, "Bind", 2)?;
                SerializeStructVariant::serialize_field(&mut state, "addr", addr)?;
                SerializeStructVariant::serialize_field(&mut state, "enclave_port", enclave_port)?;
                SerializeStructVariant::end(state)
            }
            Request::Accept { ref enclave_port } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 2u32, "Accept", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "enclave_port", enclave_port)?;
                SerializeStructVariant::end(state)
            }
            Request::Close { ref enclave_port } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 3u32, "Close", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "enclave_port", enclave_port)?;
                SerializeStructVariant::end(state)
            }
            Request::Info { ref enclave_port, ref runner_port } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 4u32, "Info", 2)?;
                SerializeStructVariant::serialize_field(&mut state, "enclave_port", enclave_port)?;
                SerializeStructVariant::serialize_field(&mut state, "runner_port", runner_port)?;
                SerializeStructVariant::end(state)
            }
        }
    }
}

/// Deserializes a `Request` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum RequestField {
            Connect,
            Bind,
            Accept,
            Close,
            Info,
        }
        struct RequestFieldVisitor;
        impl<'de> Visitor<'de> for RequestFieldVisitor {
            type Value = RequestField;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(formatter, "variant identifier")
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match value {
                    "Connect" => Ok(RequestField::Connect),
                    "Bind" => Ok(RequestField::Bind),
                    "Accept" => Ok(RequestField::Accept),
                    "Close" => Ok(RequestField::Close),
                    "Info" => Ok(RequestField::Info),
                    _ => Err(SerdeError::unknown_variant(value, VARIANTS)),
                }
            }
        }
        impl<'de> Deserialize<'de> for RequestField {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_identifier(RequestFieldVisitor)
            }
        }
        struct RequestValueVisitor<'de> {
            marker: PhantomData<Request>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for RequestValueVisitor<'de> {
            type Value = Request;
            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                Formatter::write_str(__formatter, "enum Request")
            }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match EnumAccess::variant(data)? {
                    (RequestField::Connect, variant) => {
                        enum ConnectField {
                            Addr,
                            Ignore,
                        }
                        struct ConnectFieldVisitor;
                        impl<'de> Visitor<'de> for ConnectFieldVisitor {
                            type Value = ConnectField;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "addr" => Ok(ConnectField::Addr),
                                    _ => Ok(ConnectField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for ConnectField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(ConnectFieldVisitor)
                            }
                        }
                        struct ConnectValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for ConnectValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Connect")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut addr: Option<String> = None;
                                while let Some(key) =
                                    MapAccess::next_key::<ConnectField>(&mut map)?
                                {
                                    match key {
                                        ConnectField::Addr => {
                                            if addr.is_some() {
                                                return Err(SerdeError::duplicate_field("addr"));
                                            }
                                            addr = Some(MapAccess::next_value::<String>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Connect {
                                    addr: addr.ok_or(SerdeError::missing_field("addr"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["addr"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            ConnectValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (RequestField::Bind, variant) => {
                        enum BindField {
                            Addr,
                            EnclavePort,
                            Ignore,
                        }
                        struct BindFieldVisitor;
                        impl<'de> Visitor<'de> for BindFieldVisitor {
                            type Value = BindField;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "addr" => Ok(BindField::Addr),
                                    "enclave_port" => Ok(BindField::EnclavePort),
                                    _ => Ok(BindField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for BindField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(BindFieldVisitor)
                            }
                        }
                        struct BindValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for BindValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Bind")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut addr: Option<String> = None;
                                let mut enclave_port: Option<u32> = None;
                                while let Some(key) = MapAccess::next_key::<BindField>(&mut map)? {
                                    match key {
                                        BindField::Addr => {
                                            if addr.is_some() {
                                                return Err(SerdeError::duplicate_field("addr"));
                                            }
                                            addr = Some(MapAccess::next_value::<String>(&mut map)?);
                                        }
                                        BindField::EnclavePort => {
                                            if enclave_port.is_some() {
                                                return Err(SerdeError::duplicate_field("enclave_port"));
                                            }
                                            enclave_port = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Bind {
                                    addr: addr.ok_or(SerdeError::missing_field("addr"))?,
                                    enclave_port: enclave_port.ok_or(SerdeError::missing_field("enclave_port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["addr", "enclave_port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            BindValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (RequestField::Accept, variant) => {
                        enum AcceptField {
                            EnclavePort,
                            Ignore,
                        }
                        struct AcceptFieldVisitor;
                        impl<'de> Visitor<'de> for AcceptFieldVisitor {
                            type Value = AcceptField;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "enclave_port" => Ok(AcceptField::EnclavePort),
                                    _ => Ok(AcceptField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for AcceptField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(AcceptFieldVisitor)
                            }
                        }
                        struct AcceptValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for AcceptValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Accept")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut enclave_port: Option<u32> = None;
                                while let Some(key) = MapAccess::next_key::<AcceptField>(&mut map)? {
                                    match key {
                                        AcceptField::EnclavePort => {
                                            if enclave_port.is_some() {
                                                return Err(SerdeError::duplicate_field("enclave_port"));
                                            }
                                            enclave_port = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Accept {
                                    enclave_port: enclave_port.ok_or(SerdeError::missing_field("enclave_port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["enclave_port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            AcceptValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (RequestField::Close, variant) => {
                        enum CloseField {
                            EnclavePort,
                            Ignore,
                        }
                        struct CloseFieldVisitor;
                        impl<'de> Visitor<'de> for CloseFieldVisitor {
                            type Value = CloseField;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "enclave_port" => Ok(CloseField::EnclavePort),
                                    _ => Ok(CloseField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for CloseField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(CloseFieldVisitor)
                            }
                        }
                        struct CloseVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for CloseVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, __formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(__formatter, "struct variant Request::Close")
                            }
                            #[inline]
                            fn visit_map<A>(
                                self,
                                mut map: A,
                            ) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut enclave_port: Option<u32> = None;
                                while let Some(key) = MapAccess::next_key::<CloseField>(&mut map)? {
                                    match key {
                                        CloseField::EnclavePort => {
                                            if enclave_port.is_some() {
                                                return Err(SerdeError::duplicate_field("enclave_port"));
                                            }
                                            enclave_port = Some(
                                                MapAccess::next_value::<u32>(&mut map)?
                                            );
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Close {
                                    enclave_port: enclave_port.ok_or(SerdeError::missing_field("enclave_port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["enclave_port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            CloseVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (RequestField::Info, variant) => {
                        enum InfoField {
                            EnclavePort,
                            RunnerPort,
                            Ignore,
                        }
                        struct InfoFieldVisitor;
                        impl<'de> Visitor<'de> for InfoFieldVisitor {
                            type Value = InfoField;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "enclave_port" => Ok(InfoField::EnclavePort),
                                    "runner_port" => Ok(InfoField::RunnerPort),
                                    _ => Ok(InfoField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for InfoField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(InfoFieldVisitor)
                            }
                        }
                        struct InfoValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for InfoValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Info")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut enclave_port: Option<u32> = None;
                                let mut runner_port: Option<Option<u32>> = None;
                                while let Some(key) = MapAccess::next_key::<InfoField>(&mut map)? {
                                    match key {
                                        InfoField::EnclavePort => {
                                            if enclave_port.is_some() {
                                                return Err(SerdeError::duplicate_field("enclave_port"));
                                            }
                                            enclave_port = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        InfoField::RunnerPort => {
                                            if runner_port.is_some() {
                                                return Err(SerdeError::duplicate_field("runner_port"));
                                            }
                                            runner_port = Some(MapAccess::next_value::<Option<u32>>(&mut map,)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Info {
                                    enclave_port: enclave_port.ok_or(SerdeError::missing_field("enclave_port"))?,
                                    runner_port: runner_port.ok_or(SerdeError::missing_field("runner_port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["enclave_port", "runner_port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            InfoValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                }
            }
        }
        const VARIANTS: &'static [&'static str] = &["Connect", "Bind", "Accept", "Close", "Info"];
        Deserializer::deserialize_enum(
            deserializer,
            "Request",
            VARIANTS,
            RequestValueVisitor {
                marker: PhantomData::<Request>,
                lifetime: PhantomData,
            },
        )
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
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Addr::IPv4 { ref ip, ref port } => {
                let mut serde_state =
                    Serializer::serialize_struct_variant(serializer, "Addr", 0u32, "IPv4", 2)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "ip", ip)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "port", port)?;
                SerializeStructVariant::end(serde_state)
            }
            Addr::IPv6 {
                ref ip,
                ref port,
                ref flowinfo,
                ref scope_id,
            } => {
                let mut serde_state =
                    Serializer::serialize_struct_variant(serializer, "Addr", 1u32, "IPv6", 4)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "ip", ip)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "port", port)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "flowinfo", flowinfo)?;
                SerializeStructVariant::serialize_field(&mut serde_state, "scope_id", scope_id)?;
                SerializeStructVariant::end(serde_state)
            }
        }
    }
}

/// Deserializes an `Addr` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
impl<'de> Deserialize<'de> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum AddrVariant {
            IPv4,
            IPv6,
        }
        struct AddrVariantVisitor;
        impl<'de> Visitor<'de> for AddrVariantVisitor {
            type Value = AddrVariant;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result {
                Formatter::write_str(fmt, "Addr variant identifier")
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match value {
                    "IPv4" => Ok(AddrVariant::IPv4),
                    "IPv6" => Ok(AddrVariant::IPv6),
                    _ => Err(SerdeError::unknown_variant(value, VARIANTS)),
                }
            }
        }
        impl<'de> Deserialize<'de> for AddrVariant {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(deserializer, AddrVariantVisitor)
            }
        }
        struct AddrVisitor<'de> {
            marker: PhantomData<Addr>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for AddrVisitor<'de> {
            type Value = Addr;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result {
                Formatter::write_str(fmt, "enum Addr")
            }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match EnumAccess::variant(data)? {
                    (AddrVariant::IPv4, variant) => {
                        enum IPv4Field {
                            Ip,
                            Port,
                            Ignore,
                        }
                        struct IPv4FieldVisitor;
                        impl<'de> Visitor<'de> for IPv4FieldVisitor {
                            type Value = IPv4Field;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "ip" => Ok(IPv4Field::Ip),
                                    "port" => Ok(IPv4Field::Port),
                                    _ => Ok(IPv4Field::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for IPv4Field {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                Deserializer::deserialize_identifier(deserializer, IPv4FieldVisitor)
                            }
                        }
                        struct IPv4Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for IPv4Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Addr::IPv4")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut ip: Option<[u8; 4]> = None;
                                let mut port: Option<u16> = None;
                                while let Some(key) = map.next_key()? {
                                    match key {
                                        IPv4Field::Ip => {
                                            if ip.is_some() {
                                                return Err(SerdeError::duplicate_field("ip"));
                                            }
                                            ip = Some(MapAccess::next_value::<[u8; 4]>(&mut map)?);
                                        }
                                        IPv4Field::Port => {
                                            if Option::is_some(&port) {
                                                return Err(SerdeError::duplicate_field("port"));
                                            }
                                            port = Some(MapAccess::next_value::<u16>(&mut map)?);
                                        }
                                        _ => {
                                            map.next_value()?;
                                        }
                                    }
                                }
                                Ok(Addr::IPv4 {
                                    ip: ip.ok_or(SerdeError::missing_field("ip"))?,
                                    port: port.ok_or(SerdeError::missing_field("port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["ip", "port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            IPv4Visitor {
                                marker: PhantomData::<Addr>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (AddrVariant::IPv6, variant) => {
                        enum IPv6Field {
                            Ip,
                            Port,
                            Flowinfo,
                            ScopeId,
                            Ignore,
                        }
                        struct IPv6FieldVisitor;
                        impl<'de> Visitor<'de> for IPv6FieldVisitor {
                            type Value = IPv6Field;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "ip" => Ok(IPv6Field::Ip),
                                    "port" => Ok(IPv6Field::Port),
                                    "flowinfo" => Ok(IPv6Field::Flowinfo),
                                    "scope_id" => Ok(IPv6Field::ScopeId),
                                    _ => Ok(IPv6Field::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for IPv6Field {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                Deserializer::deserialize_identifier(deserializer, IPv6FieldVisitor)
                            }
                        }

                        struct IPv6Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for IPv6Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Addr::IPv6")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut ip: Option<[u8; 16]> = None;
                                let mut port: Option<u16> = None;
                                let mut flowinfo: Option<u32> = None;
                                let mut scope_id: Option<u32> = None;
                                while let Some(key) = MapAccess::next_key::<IPv6Field>(&mut map)? {
                                    match key {
                                        IPv6Field::Ip => {
                                            if ip.is_some() {
                                                return Err(SerdeError::duplicate_field("ip"));
                                            }
                                            ip = Some(MapAccess::next_value::<[u8; 16]>(&mut map)?);
                                        }
                                        IPv6Field::Port => {
                                            if port.is_some() {
                                                return Err(SerdeError::duplicate_field("port"));
                                            }
                                            port = Some(MapAccess::next_value::<u16>(&mut map)?);
                                        }
                                        IPv6Field::Flowinfo => {
                                            if flowinfo.is_some() {
                                                return Err(SerdeError::duplicate_field("flowinfo"));
                                            }
                                            flowinfo = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        IPv6Field::ScopeId => {
                                            if scope_id.is_some() {
                                                return Err(SerdeError::duplicate_field("scope_id"));
                                            }
                                            scope_id = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Addr::IPv6 {
                                    ip: ip.ok_or(SerdeError::missing_field("ip"))?,
                                    port: port.ok_or(SerdeError::missing_field("port"))?,
                                    flowinfo: flowinfo.ok_or(SerdeError::missing_field("flowinfo"))?,
                                    scope_id: scope_id.ok_or(SerdeError::missing_field("scop_id"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] =
                            &["ip", "port", "flowinfo", "scope_id"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            IPv6Visitor {
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
            deserializer,
            "Addr",
            VARIANTS,
            AddrVisitor {
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

#[derive(Debug, PartialEq, Eq, Deserialize)]
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

/// Serializes a `Response` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Response::Connected {
                ref proxy_port,
                ref local,
                ref peer,
            } => {
                let mut state =
                    Serializer::serialize_struct_variant(serializer, "Response", 0u32, "Connected", 3)?;
                SerializeStructVariant::serialize_field(&mut state, "proxy_port", proxy_port)?;
                SerializeStructVariant::serialize_field(&mut state, "local", local)?;
                SerializeStructVariant::serialize_field(&mut state, "peer", peer)?;
                SerializeStructVariant::end(state)
            }
            Response::Bound { ref local } => {
                let mut state =
                    Serializer::serialize_struct_variant(serializer, "Response", 1u32, "Bound", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "local", local)?;
                SerializeStructVariant::end(state)
            }
            Response::IncomingConnection {
                ref local,
                ref peer,
                ref proxy_port,
            } => {
                let mut state =
                    Serializer::serialize_struct_variant(serializer, "Response", 2u32, "IncomingConnection", 3)?;
                SerializeStructVariant::serialize_field(&mut state, "local", local)?;
                SerializeStructVariant::serialize_field(&mut state, "peer", peer)?;
                SerializeStructVariant::serialize_field(&mut state, "proxy_port", proxy_port)?;
                SerializeStructVariant::end(state)
            }
            Response::Closed => {
                Serializer::serialize_unit_variant(serializer, "Response", 3u32, "Closed")
            }
            Response::Info {
                ref local,
                ref peer,
            } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Response", 4u32, "Info", 2)?;
                SerializeStructVariant::serialize_field(&mut state, "local", local)?;
                SerializeStructVariant::serialize_field(&mut state, "peer", peer)?;
                SerializeStructVariant::end(state)
            }
            Response::Failed(ref __field0) =>
                Serializer::serialize_newtype_variant(serializer, "Response", 5u32, "Failed", __field0),
        }
    }
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
            Error::ConnectionNotFound =>
                Serializer::serialize_unit_variant(serializer, "Error", 0u32, "ConnectionNotFound"),
            Error::SystemError(ref errno) =>
                Serializer::serialize_newtype_variant(serializer, "Error", 1u32, "SystemError", errno,),
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
impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        pub enum ErrorVariant {
            ConnectionNotFound,
            SystemError,
            Unknown,
            VsockError,
        }
        struct ErrorVariantVisitor;
        impl<'de> Visitor<'de> for ErrorVariantVisitor {
            type Value = ErrorVariant;

            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result {
                Formatter::write_str(fmt, "Error variant identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match value {
                    "ConnectionNotFound" => Ok(ErrorVariant::ConnectionNotFound),
                    "SystemError" => Ok(ErrorVariant::SystemError),
                    "Unknown" => Ok(ErrorVariant::Unknown),
                    "VsockError" => Ok(ErrorVariant::VsockError),
                    _ => Err(SerdeError::unknown_variant(value, VARIANTS)),
                }
            }
        }
        impl<'de> Deserialize<'de> for ErrorVariant {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(deserializer, ErrorVariantVisitor)
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
                    (ErrorVariant::ConnectionNotFound, val) => {
                        VariantAccess::unit_variant(val)?;
                        Ok(Error::ConnectionNotFound)
                    }
                    (ErrorVariant::SystemError, val) =>
                        VariantAccess::newtype_variant::<i32>(val).map(Error::SystemError),
                    (ErrorVariant::Unknown, val) => {
                        VariantAccess::unit_variant(val)?;
                        Ok(Error::Unknown)
                    }
                    (ErrorVariant::VsockError, val) => {
                        VariantAccess::unit_variant(val)?;
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
    use crate::{Addr, Error, Response, Request};

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

    #[test]
    fn test_response_encoding() {
        let data: Vec<(Response, Vec<u8>)> = Vec::from([
            (
                Response::Connected {
                    proxy_port: 0,
                    local: Addr::IPv4 {
                        ip: [1, 2, 3, 4],
                        port: 3,
                    },
                    peer: Addr::IPv6 {
                        ip: [1; 16],
                        port: 2,
                        flowinfo: 3,
                        scope_id: 4,
                    },
                },
                Vec::from([
                    0xa1, 0x69, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0xa3, 0x6a,
                    0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x00, 0x65, 0x6c,
                    0x6f, 0x63, 0x61, 0x6c, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x34, 0xa2, 0x62, 0x69,
                    0x70, 0x84, 0x01, 0x02, 0x03, 0x04, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x03, 0x64,
                    0x70, 0x65, 0x65, 0x72, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69,
                    0x70, 0x90, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x02, 0x68, 0x66,
                    0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x66, 0x6f, 0x03, 0x68, 0x73, 0x63, 0x6f, 0x70,
                    0x65, 0x5f, 0x69, 0x64, 0x04,
                ]),
            ),
            (
                Response::Bound {
                    local: Addr::IPv4 {
                        ip: [1, 2, 3, 4],
                        port: 3,
                    },
                },
                Vec::from([
                    0xa1, 0x65, 0x42, 0x6f, 0x75, 0x6e, 0x64, 0xa1, 0x65, 0x6c, 0x6f, 0x63, 0x61,
                    0x6c, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x34, 0xa2, 0x62, 0x69, 0x70, 0x84, 0x01,
                    0x02, 0x03, 0x04, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x03,
                ]),
            ),
            (
                Response::IncomingConnection {
                    local: Addr::IPv6 {
                        ip: [1; 16],
                        port: 2,
                        flowinfo: 3,
                        scope_id: 4,
                    },
                    peer: Addr::IPv4 {
                        ip: [1, 2, 3, 4],
                        port: 3,
                    },
                    proxy_port: 22,
                },
                Vec::from([
                    0xa1, 0x72, 0x49, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e,
                    0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0xa3, 0x65, 0x6c, 0x6f, 0x63, 0x61,
                    0x6c, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69, 0x70, 0x90, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x02, 0x68, 0x66, 0x6c, 0x6f, 0x77,
                    0x69, 0x6e, 0x66, 0x6f, 0x03, 0x68, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69,
                    0x64, 0x04, 0x64, 0x70, 0x65, 0x65, 0x72, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x34,
                    0xa2, 0x62, 0x69, 0x70, 0x84, 0x01, 0x02, 0x03, 0x04, 0x64, 0x70, 0x6f, 0x72,
                    0x74, 0x03, 0x6a, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x70, 0x6f, 0x72, 0x74,
                    0x16,
                ]),
            ),
            (
                Response::Closed,
                Vec::from([0x66, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64]),
            ),
            (
                Response::Info {
                    local: Addr::IPv6 {
                        ip: [1; 16],
                        port: 2,
                        flowinfo: 3,
                        scope_id: 4,
                    },
                    peer: None,
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0xa2, 0x65, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
                    0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69, 0x70, 0x90, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x02, 0x68, 0x66, 0x6c, 0x6f, 0x77, 0x69,
                    0x6e, 0x66, 0x6f, 0x03, 0x68, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
                    0x04, 0x64, 0x70, 0x65, 0x65, 0x72, 0xf6,
                ]),
            ),
            (
                Response::Info {
                    local: Addr::IPv6 {
                        ip: [1; 16],
                        port: 2,
                        flowinfo: 3,
                        scope_id: 4,
                    },
                    peer: Some(Addr::IPv6 {
                        ip: [2; 16],
                        port: 3,
                        flowinfo: 4,
                        scope_id: 5,
                    }),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0xa2, 0x65, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
                    0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4, 0x62, 0x69, 0x70, 0x90, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x02, 0x68, 0x66, 0x6c, 0x6f, 0x77, 0x69,
                    0x6e, 0x66, 0x6f, 0x03, 0x68, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64,
                    0x04, 0x64, 0x70, 0x65, 0x65, 0x72, 0xa1, 0x64, 0x49, 0x50, 0x76, 0x36, 0xa4,
                    0x62, 0x69, 0x70, 0x90, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x03,
                    0x68, 0x66, 0x6c, 0x6f, 0x77, 0x69, 0x6e, 0x66, 0x6f, 0x04, 0x68, 0x73, 0x63,
                    0x6f, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x05,
                ]),
            ),
            (
                Response::Failed(Error::ConnectionNotFound),
                Vec::from([
                    0xa1, 0x66, 0x46, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x72, 0x43, 0x6f, 0x6e, 0x6e,
                    0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e,
                    0x64,
                ]),
            ),
        ]);

        for (resp, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(resp).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Response>(&bin).unwrap(), *resp);
        }
    }
}
