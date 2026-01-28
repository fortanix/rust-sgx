#![deny(warnings)]
#![no_std]

#[cfg(feature="std")]
extern crate std;

#[cfg(all(feature="alloc", not(feature="std")))]
use {
    alloc::string::String,
    alloc::vec::Vec,
};
#[cfg(all(feature="std", not(feature="alloc")))]
use {
    std::string::String,
    std::vec::Vec,
};

#[cfg(feature="core")]
use core::net::{IpAddr, SocketAddr};
#[cfg(all(feature="std", not(feature="core")))]
use std::net::{IpAddr, SocketAddr};
#[cfg(feature="serde")]
use {
    core::fmt::{self, Formatter},
    core::marker::PhantomData,

    serde::{Deserialize, Deserializer, Serialize, Serializer},
    serde::ser::SerializeStructVariant,
    serde::de::{EnumAccess, Error as SerdeError, IgnoredAny, MapAccess, VariantAccess, Visitor},
};

#[cfg(feature="std")]
use {
    std::io,
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
    Exit {
        code: i32,
    },
    Init,
}

/// Serializes a `Request` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
#[cfg(feature="serde")]
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
            Request::Exit { ref code } => {
                let mut state = Serializer::serialize_struct_variant(serializer, "Request", 5u32, "Exit", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "code", code)?;
                SerializeStructVariant::end(state)
            }
            Request::Init => {
                let state = Serializer::serialize_struct_variant(serializer, "Request", 5u32, "Init", 0)?;
                SerializeStructVariant::end(state)
            }
        }
    }
}

/// Deserializes a `Request` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
#[cfg(feature="serde")]
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
            Exit,
            Init,
        }
        struct RequestFieldVisitor;
        impl<'de> Visitor<'de> for RequestFieldVisitor {
            type Value = RequestField;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                    "Exit" => Ok(RequestField::Exit),
                    "Init" => Ok(RequestField::Init),
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
            fn expecting(&self, __formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, __formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                    (RequestField::Exit, variant) => {
                        enum ExitField {
                            Code,
                            Ignore,
                        }
                        struct ExitFieldVisitor;
                        impl<'de> Visitor<'de> for ExitFieldVisitor {
                            type Value = ExitField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "code" => Ok(ExitField::Code),
                                    _ => Ok(ExitField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for ExitField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(ExitFieldVisitor)
                            }
                        }
                        struct ExitValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for ExitValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Exit")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut code: Option<i32> = None;
                                while let Some(key) =
                                    MapAccess::next_key::<ExitField>(&mut map)?
                                {
                                    match key {
                                        ExitField::Code => {
                                            if code.is_some() {
                                                return Err(SerdeError::duplicate_field("code"));
                                            }
                                            code = Some(MapAccess::next_value::<i32>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Exit {
                                    code: code.ok_or(SerdeError::missing_field("code"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["code"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            ExitValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (RequestField::Init, variant) => {
                        enum InitField {
                            Ignore,
                        }
                        struct InitFieldVisitor;
                        impl<'de> Visitor<'de> for InitFieldVisitor {
                            type Value = InitField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    _ => Ok(InitField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for InitField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(InitFieldVisitor)
                            }
                        }
                        struct InitValueVisitor<'de> {
                            marker: PhantomData<Request>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for InitValueVisitor<'de> {
                            type Value = Request;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Request::Init")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                while let Some(key) =
                                    MapAccess::next_key::<InitField>(&mut map)?
                                {
                                    match key {
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Request::Init {
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &[];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            InitValueVisitor {
                                marker: PhantomData::<Request>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                }
            }
        }
        const VARIANTS: &'static [&'static str] = &["Connect", "Bind", "Accept", "Close", "Info", "Exit", "Init"];
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
#[cfg(feature="serde")]
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
#[cfg(feature="serde")]
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
            fn expecting(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
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
                deserializer.deserialize_identifier(AddrVariantVisitor)
            }
        }
        struct AddrVisitor<'de> {
            marker: PhantomData<Addr>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for AddrVisitor<'de> {
            type Value = Addr;
            fn expecting(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                                deserializer.deserialize_identifier(IPv4FieldVisitor)
                            }
                        }
                        struct IPv4Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for IPv4Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                                            map.next_value::<()>()?;
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
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                                deserializer.deserialize_identifier(IPv6FieldVisitor)
                            }
                        }

                        struct IPv6Visitor<'de> {
                            marker: PhantomData<Addr>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for IPv6Visitor<'de> {
                            type Value = Addr;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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

#[cfg(any(feature="core", feature="std"))]
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

#[cfg(any(feature="core", feature="std"))]
impl From<Addr> for SocketAddr {
    fn from(addr: Addr) -> SocketAddr {
        match addr {
            Addr::IPv4{ ip, port } => {
                SocketAddr::new(IpAddr::V4(ip.into()), port)
            },
            Addr::IPv6{ ip, port, .. } => {
                SocketAddr::new(IpAddr::V6(ip.into()), port)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
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
    // TODO Split up failed command (e.g., bind executed on behalve of runner errored) and
    // errored runner (e.g., no info was found for fd).
    Failed(Error),
    Init {
        args: Vec<String>,
    },
}

/// Serializes a `Response` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
#[cfg(feature="serde")]
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
            Response::Init { ref args } => {
                let mut state =
                    Serializer::serialize_struct_variant(serializer, "Response", 6u32, "Init", 1)?;
                SerializeStructVariant::serialize_field(&mut state, "args", args)?;
                SerializeStructVariant::end(state)
            }
        }
    }
}

/// Deserializes a `Response` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Deserialize` macro.
#[cfg(feature="serde")]
impl<'de> Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[allow(non_camel_case_types)]
        enum ResponseField {
            Connected,
            Bound,
            IncomingConnection,
            Closed,
            Info,
            Failed,
            Init,
        }
        struct ResponseFieldVisitor;
        impl<'de> Visitor<'de> for ResponseFieldVisitor {
            type Value = ResponseField;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                Formatter::write_str(formatter, "variant identifier")
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match value {
                    "Connected" => Ok(ResponseField::Connected),
                    "Bound" => Ok(ResponseField::Bound),
                    "IncomingConnection" => Ok(ResponseField::IncomingConnection),
                    "Closed" => Ok(ResponseField::Closed),
                    "Info" => Ok(ResponseField::Info),
                    "Failed" => Ok(ResponseField::Failed),
                    "Init" => Ok(ResponseField::Init),
                    _ => Err(SerdeError::unknown_variant(value, VARIANTS)),
                }
            }
        }
        impl<'de> Deserialize<'de> for ResponseField {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_identifier(ResponseFieldVisitor)
            }
        }
        struct ResponseValueVisitor<'de> {
            marker: PhantomData<Response>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de> Visitor<'de> for ResponseValueVisitor<'de> {
            type Value = Response;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                Formatter::write_str(formatter, "enum Response")
            }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match EnumAccess::variant(data)? {
                    (ResponseField::Connected, variant) => {
                        enum ConnectedField {
                            ProxyPort,
                            Local,
                            Peer,
                            Ignore,
                        }
                        struct ConnectedFieldVisitor;
                        impl<'de> Visitor<'de> for ConnectedFieldVisitor {
                            type Value = ConnectedField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "proxy_port" => Ok(ConnectedField::ProxyPort),
                                    "local" => Ok(ConnectedField::Local),
                                    "peer" => Ok(ConnectedField::Peer),
                                    _ => Ok(ConnectedField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for ConnectedField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(ConnectedFieldVisitor)
                            }
                        }
                        struct ConnectedValueVisitor<'de> {
                            marker: PhantomData<Response>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for ConnectedValueVisitor<'de> {
                            type Value = Response;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Response::Connected")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A,) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut proxy_port: Option<u32> = None;
                                let mut local: Option<Addr> = None;
                                let mut peer: Option<Addr> = None;
                                while let Some(key) = MapAccess::next_key::<ConnectedField>(&mut map)? {
                                    match key {
                                        ConnectedField::ProxyPort => {
                                            if proxy_port.is_some() {
                                                return Err(SerdeError::duplicate_field("proxy_port"));
                                            }
                                            proxy_port = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        ConnectedField::Local => {
                                            if local.is_some() {
                                                return Err(SerdeError::duplicate_field("local"));
                                            }
                                            local = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        ConnectedField::Peer => {
                                            if peer.is_some() {
                                                return Err(SerdeError::duplicate_field("peer"));
                                            }
                                            peer = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Response::Connected {
                                    proxy_port: proxy_port.ok_or(SerdeError::missing_field("proxy_port"))?,
                                    local: local.ok_or(SerdeError::missing_field("local"))?,
                                    peer: peer.ok_or(SerdeError::missing_field("peer"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["proxy_port", "local", "peer"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            ConnectedValueVisitor {
                                marker: PhantomData::<Response>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (ResponseField::Bound, variant) => {
                        #[allow(non_camel_case_types)]
                        enum BoundField {
                            Local,
                            Ignore,
                        }
                        struct BoundFieldVisitor;
                        impl<'de> Visitor<'de> for BoundFieldVisitor {
                            type Value = BoundField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "local" => Ok(BoundField::Local),
                                    _ => Ok(BoundField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for BoundField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(BoundFieldVisitor)
                            }
                        }
                        struct BoundValueVisitor<'de> {
                            marker: PhantomData<Response>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for BoundValueVisitor<'de> {
                            type Value = Response;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Response::Bound")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut local: Option<Addr> = None;
                                while let Some(key) = MapAccess::next_key::<BoundField>(&mut map)? {
                                    match key {
                                        BoundField::Local => {
                                            if local.is_some() {
                                                return Err(SerdeError::duplicate_field("local"));
                                            }
                                            local = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Response::Bound {
                                    local: local.ok_or(SerdeError::missing_field("local"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["local"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            BoundValueVisitor {
                                marker: PhantomData::<Response>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (ResponseField::IncomingConnection, variant) => {
                        #[allow(non_camel_case_types)]
                        enum IncomingConnectionField {
                            Local,
                            Peer,
                            ProxyPort,
                            Ignore,
                        }
                        struct IncomingConnectionFieldVisitor;
                        impl<'de> Visitor<'de> for IncomingConnectionFieldVisitor {
                            type Value = IncomingConnectionField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "local" => Ok(IncomingConnectionField::Local),
                                    "peer" => Ok(IncomingConnectionField::Peer),
                                    "proxy_port" => Ok(IncomingConnectionField::ProxyPort),
                                    _ => Ok(IncomingConnectionField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for IncomingConnectionField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(IncomingConnectionFieldVisitor)
                            }
                        }
                        struct IncomingConnectionValueVisitor<'de> {
                            marker: PhantomData<Response>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for IncomingConnectionValueVisitor<'de> {
                            type Value = Response;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Response::IncomingConnection")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut local: Option<Addr> = None;
                                let mut peer: Option<Addr> = None;
                                let mut proxy_port: Option<u32> = None;
                                while let Some(key) = MapAccess::next_key::<IncomingConnectionField>(&mut map)?
                                {
                                    match key {
                                        IncomingConnectionField::Local => {
                                            if local.is_some() {
                                                return Err(SerdeError::duplicate_field("local"));
                                            }
                                            local = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        IncomingConnectionField::Peer => {
                                            if peer.is_some() {
                                                return Err(SerdeError::duplicate_field("peer"));
                                            }
                                            peer = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        IncomingConnectionField::ProxyPort => {
                                            if proxy_port.is_some() {
                                                return Err(SerdeError::duplicate_field("proxy_port"));
                                            }
                                            proxy_port = Some(MapAccess::next_value::<u32>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Response::IncomingConnection {
                                    local: local.ok_or(SerdeError::missing_field("local"))?,
                                    peer: peer.ok_or(SerdeError::missing_field("peer"))?,
                                    proxy_port: proxy_port.ok_or(SerdeError::missing_field("proxy_port"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["local", "peer", "proxy_port"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            IncomingConnectionValueVisitor {
                                marker: PhantomData::<Response>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (ResponseField::Closed, variant) => {
                        VariantAccess::unit_variant(variant)?;
                        Ok(Response::Closed)
                    }
                    (ResponseField::Info, variant) => {
                        enum InfoField {
                            Local,
                            Peer,
                            Ignore,
                        }
                        struct InfoFieldVisitor;
                        impl<'de> Visitor<'de> for InfoFieldVisitor {
                            type Value = InfoField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "local" => Ok(InfoField::Local),
                                    "peer" => Ok(InfoField::Peer),
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
                        struct InfoVisitor<'de> {
                            marker: PhantomData<Response>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for InfoVisitor<'de> {
                            type Value = Response;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Response::Info")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut local: Option<Addr> = None;
                                let mut peer: Option<Option<Addr>> = None;
                                while let Some(key) = MapAccess::next_key::<InfoField>(&mut map)? {
                                    match key {
                                        InfoField::Local => {
                                            if local.is_some() {
                                                return Err(SerdeError::duplicate_field("local"));
                                            }
                                            local = Some(MapAccess::next_value::<Addr>(&mut map)?);
                                        }
                                        InfoField::Peer => {
                                            if peer.is_some() {
                                                return Err(SerdeError::duplicate_field("peer"));
                                            }
                                            peer = Some(MapAccess::next_value::<Option<Addr>>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Response::Info {
                                    local: local.ok_or(SerdeError::missing_field("local"))?,
                                    peer: peer.ok_or(SerdeError::missing_field("peer"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["local", "peer"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            InfoVisitor {
                                marker: PhantomData::<Response>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                    (ResponseField::Failed, variant) => {
                        variant.newtype_variant()
                            .map(|e| Response::Failed(e))
                    }
                    (ResponseField::Init, variant) => {
                        enum InitField {
                            Args,
                            Ignore,
                        }
                        struct InitFieldVisitor;
                        impl<'de> Visitor<'de> for InitFieldVisitor {
                            type Value = InitField;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "field identifier")
                            }
                            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                            where
                                E: SerdeError,
                            {
                                match value {
                                    "args" => Ok(InitField::Args),
                                    _ => Ok(InitField::Ignore),
                                }
                            }
                        }
                        impl<'de> Deserialize<'de> for InitField {
                            #[inline]
                            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                            where
                                D: Deserializer<'de>,
                            {
                                deserializer.deserialize_identifier(InitFieldVisitor)
                            }
                        }
                        struct InitValueVisitor<'de> {
                            marker: PhantomData<Response>,
                            lifetime: PhantomData<&'de ()>,
                        }
                        impl<'de> Visitor<'de> for InitValueVisitor<'de> {
                            type Value = Response;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                Formatter::write_str(formatter, "struct variant Response::Init")
                            }
                            #[inline]
                            fn visit_map<A>(self, mut map: A,) -> Result<Self::Value, A::Error>
                            where
                                A: MapAccess<'de>,
                            {
                                let mut args: Option<Vec<String>> = None;
                                while let Some(key) = MapAccess::next_key::<InitField>(&mut map)? {
                                    match key {
                                        InitField::Args => {
                                            if args.is_some() {
                                                return Err(SerdeError::duplicate_field("args"));
                                            }
                                            args = Some(MapAccess::next_value::<Vec<String>>(&mut map)?);
                                        }
                                        _ => {
                                            MapAccess::next_value::<IgnoredAny>(&mut map)?;
                                        }
                                    }
                                }
                                Ok(Response::Init {
                                    args: args.ok_or(SerdeError::missing_field("args"))?,
                                })
                            }
                        }
                        const FIELDS: &'static [&'static str] = &["args"];
                        VariantAccess::struct_variant(
                            variant,
                            FIELDS,
                            InitValueVisitor {
                                marker: PhantomData::<Response>,
                                lifetime: PhantomData,
                            },
                        )
                    }
                }
            }
        }
        const VARIANTS: &'static [&'static str] = &[
            "Connected",
            "Bound",
            "IncomingConnection",
            "Closed",
            "Info",
            "Failed",
            "Init",
        ];
        Deserializer::deserialize_enum(
            deserializer,
            "Response",
            VARIANTS,
            ResponseValueVisitor {
                marker: PhantomData::<Response>,
                lifetime: PhantomData,
            },
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    FilesystemLoop,
    StaleNetworkFileHandle,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    StorageFull,
    NotSeekable,
    FilesystemQuotaExceeded,
    FileTooLarge,
    ResourceBusy,
    ExecutableFileBusy,
    Deadlock,
    CrossesDevices,
    TooManyLinks,
    //FilenameTooLong,
    ArgumentListTooLong,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
    Uncategorized,
}

#[cfg(feature="std")]
impl From<io::ErrorKind> for ErrorKind {
    fn from(kind: io::ErrorKind) -> ErrorKind {
        match kind {
            io::ErrorKind::NotFound => ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused => ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset => ErrorKind::ConnectionReset,
            // Unstable std library feature io_error_more
            //io::ErrorKind::HostUnreachable => ErrorKind::HostUnreachable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NetworkUnreachable => ErrorKind::NetworkUnreachable,
            io::ErrorKind::ConnectionAborted => ErrorKind::ConnectionAborted,
            io::ErrorKind::NotConnected => ErrorKind::NotConnected,
            io::ErrorKind::AddrInUse => ErrorKind::AddrInUse,
            io::ErrorKind::AddrNotAvailable => ErrorKind::AddrNotAvailable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NetworkDown => ErrorKind::NetworkDown,
            io::ErrorKind::BrokenPipe => ErrorKind::BrokenPipe,
            io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
            io::ErrorKind::WouldBlock => ErrorKind::WouldBlock,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NotADirectory => ErrorKind::NotADirectory,
            // Unstable std library feature io_error_more
            //io::ErrorKind::IsADirectory => ErrorKind::IsADirectory,
            // Unstable std library feature io_error_more
            //io::ErrorKind::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ReadOnlyFilesystem => ErrorKind::ReadOnlyFilesystem,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FilesystemLoop => ErrorKind::FilesystemLoop,
            // Unstable std library feature io_error_more
            //io::ErrorKind::StaleNetworkFileHandle => ErrorKind::StaleNetworkFileHandle,
            io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
            io::ErrorKind::InvalidData => ErrorKind::InvalidData,
            io::ErrorKind::TimedOut => ErrorKind::TimedOut,
            io::ErrorKind::WriteZero => ErrorKind::WriteZero,
            // Unstable std library feature io_error_more
            //io::ErrorKind::StorageFull => ErrorKind::StorageFull,
            // Unstable std library feature io_error_more
            //io::ErrorKind::NotSeekable => ErrorKind::NotSeekable,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FilesystemQuotaExceeded => ErrorKind::FilesystemQuotaExceeded,
            // Unstable std library feature io_error_more
            //io::ErrorKind::FileTooLarge => ErrorKind::FileTooLarge,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ResourceBusy => ErrorKind::ResourceBusy,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ExecutableFileBusy => ErrorKind::ExecutableFileBusy,
            // Unstable std library feature io_error_more
            //io::ErrorKind::Deadlock => ErrorKind::Deadlock,
            // Unstable std library feature io_error_more
            //io::ErrorKind::CrossesDevices => ErrorKind::CrossesDevices,
            // Unstable std library feature io_error_more
            //io::ErrorKind::TooManyLinks => ErrorKind::TooManyLinks,
            // Unstable std library feature
            //io::ErrorKind::FilenameTooLong => ErrorKind::FilenameTooLong,
            // Unstable std library feature io_error_more
            //io::ErrorKind::ArgumentListTooLong => ErrorKind::ArgumentListTooLong,
            io::ErrorKind::Interrupted => ErrorKind::Interrupted,
            io::ErrorKind::Unsupported => ErrorKind::Unsupported,
            io::ErrorKind::UnexpectedEof => ErrorKind::UnexpectedEof,
            io::ErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
            io::ErrorKind::Other => ErrorKind::Other,
            // Unstable std library feature io_error_uncategorized
            //io::ErrorKind::Uncategorized => ErrorKind::Uncategorized,
            _ => ErrorKind::Other,
        }
    }
}

#[cfg(feature="serde")]
impl Serialize for ErrorKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ErrorKind::NotFound =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 0u32, "NotFound"),
            ErrorKind::PermissionDenied =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 1u32, "PermissionDenied"),
            ErrorKind::ConnectionRefused =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 2u32, "ConnectionRefused"),
            ErrorKind::ConnectionReset =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 3u32, "ConnectionReset"),
            ErrorKind::HostUnreachable =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 4u32, "HostUnreachable"),
            ErrorKind::NetworkUnreachable =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 5u32, "NetworkUnreachable"),
            ErrorKind::ConnectionAborted =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 6u32, "ConnectionAborted"),
            ErrorKind::NotConnected =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 7u32, "NotConnected"),
            ErrorKind::AddrInUse =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 8u32, "AddrInUse"),
            ErrorKind::AddrNotAvailable =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 9u32, "AddrNotAvailable"),
            ErrorKind::NetworkDown =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 10u32, "NetworkDown"),
            ErrorKind::BrokenPipe =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 11u32, "BrokenPipe"),
            ErrorKind::AlreadyExists =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 12u32, "AlreadyExists"),
            ErrorKind::WouldBlock =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 13u32, "WouldBlock"),
            ErrorKind::NotADirectory =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 14u32, "NotADirectory"),
            ErrorKind::IsADirectory =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 15u32, "IsADirectory"),
            ErrorKind::DirectoryNotEmpty =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 16u32, "DirectoryNotEmpty"),
            ErrorKind::ReadOnlyFilesystem =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 17u32, "ReadOnlyFilesystem"),
            ErrorKind::FilesystemLoop =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 18u32, "FilesystemLoop"),
            ErrorKind::StaleNetworkFileHandle =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 19u32, "StaleNetworkFileHandle"),
            ErrorKind::InvalidInput =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 20u32, "InvalidInput"),
            ErrorKind::InvalidData =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 21u32, "InvalidData"),
            ErrorKind::TimedOut =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 22u32, "TimedOut"),
            ErrorKind::WriteZero =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 23u32, "WriteZero"),
            ErrorKind::StorageFull =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 24u32, "StorageFull"),
            ErrorKind::NotSeekable =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 25u32, "NotSeekable"),
            ErrorKind::FilesystemQuotaExceeded =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 26u32, "FilesystemQuotaExceeded"),
            ErrorKind::FileTooLarge =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 27u32, "FileTooLarge"),
            ErrorKind::ResourceBusy =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 28u32, "ResourceBusy"),
            ErrorKind::ExecutableFileBusy =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 29u32, "ExecutableFileBusy"),
            ErrorKind::Deadlock =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 30u32, "Deadlock"),
            ErrorKind::CrossesDevices =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 31u32, "CrossesDevices"),
            ErrorKind::TooManyLinks =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 32u32, "TooManyLinks"),
            //ErrorKind::FilenameTooLong =>
            //    Serializer::serialize_unit_variant(serializer, "ErrorKind", 33u32, "FilenameTooLong"),
            ErrorKind::ArgumentListTooLong =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 34u32, "ArgumentListTooLong"),
            ErrorKind::Interrupted =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 35u32, "Interrupted"),
            ErrorKind::Unsupported =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 36u32, "Unsupported"),
            ErrorKind::UnexpectedEof =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 37u32, "UnexpectedEof"),
            ErrorKind::OutOfMemory =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 38u32, "OutOfMemory"),
            ErrorKind::Other =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 39u32, "Other"),
            ErrorKind::Uncategorized =>
                Serializer::serialize_unit_variant(serializer, "ErrorKind", 40u32, "Uncategorized"),
        }
    }
}

#[cfg(feature="serde")]
impl<'de> Deserialize<'de> for ErrorKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        pub struct ErrorKindVariant(ErrorKind);

        struct ErrorKindVariantVisitor;
        impl<'de> Visitor<'de> for ErrorKindVariantVisitor {
            type Value = ErrorKindVariant;

            fn expecting(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
                Formatter::write_str(fmt, "ErrorKind variant identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                match value {
                    "NotFound" => Ok(ErrorKindVariant(ErrorKind::NotFound)),
                    "PermissionDenied" => Ok(ErrorKindVariant(ErrorKind::PermissionDenied)),
                    "ConnectionRefused" => Ok(ErrorKindVariant(ErrorKind::ConnectionRefused)),
                    "ConnectionReset" => Ok(ErrorKindVariant(ErrorKind::ConnectionReset)),
                    "HostUnreachable" => Ok(ErrorKindVariant(ErrorKind::HostUnreachable)),
                    "NetworkUnreachable" => Ok(ErrorKindVariant(ErrorKind::NetworkUnreachable)),
                    "ConnectionAborted" => Ok(ErrorKindVariant(ErrorKind::ConnectionAborted)),
                    "NotConnected" => Ok(ErrorKindVariant(ErrorKind::NotConnected)),
                    "AddrInUse" => Ok(ErrorKindVariant(ErrorKind::AddrInUse)),
                    "AddrNotAvailable" => Ok(ErrorKindVariant(ErrorKind::AddrNotAvailable)),
                    "NetworkDown" => Ok(ErrorKindVariant(ErrorKind::NetworkDown)),
                    "BrokenPipe" => Ok(ErrorKindVariant(ErrorKind::BrokenPipe)),
                    "AlreadyExists" => Ok(ErrorKindVariant(ErrorKind::AlreadyExists)),
                    "WouldBlock" => Ok(ErrorKindVariant(ErrorKind::WouldBlock)),
                    "NotADirectory" => Ok(ErrorKindVariant(ErrorKind::NotADirectory)),
                    "IsADirectory" => Ok(ErrorKindVariant(ErrorKind::IsADirectory)),
                    "DirectoryNotEmpty" => Ok(ErrorKindVariant(ErrorKind::DirectoryNotEmpty)),
                    "ReadOnlyFilesystem" => Ok(ErrorKindVariant(ErrorKind::ReadOnlyFilesystem)),
                    "FilesystemLoop" => Ok(ErrorKindVariant(ErrorKind::FilesystemLoop)),
                    "StaleNetworkFileHandle" => Ok(ErrorKindVariant(ErrorKind::StaleNetworkFileHandle)),
                    "InvalidInput" => Ok(ErrorKindVariant(ErrorKind::InvalidInput)),
                    "InvalidData" => Ok(ErrorKindVariant(ErrorKind::InvalidData)),
                    "TimedOut" => Ok(ErrorKindVariant(ErrorKind::TimedOut)),
                    "WriteZero" => Ok(ErrorKindVariant(ErrorKind::WriteZero)),
                    "StorageFull" => Ok(ErrorKindVariant(ErrorKind::StorageFull)),
                    "NotSeekable" => Ok(ErrorKindVariant(ErrorKind::NotSeekable)),
                    "FilesystemQuotaExceeded" => Ok(ErrorKindVariant(ErrorKind::FilesystemQuotaExceeded)),
                    "FileTooLarge" => Ok(ErrorKindVariant(ErrorKind::FileTooLarge)),
                    "ResourceBusy" => Ok(ErrorKindVariant(ErrorKind::ResourceBusy)),
                    "ExecutableFileBusy" => Ok(ErrorKindVariant(ErrorKind::ExecutableFileBusy)),
                    "Deadlock" => Ok(ErrorKindVariant(ErrorKind::Deadlock)),
                    "CrossesDevices" => Ok(ErrorKindVariant(ErrorKind::CrossesDevices)),
                    "TooManyLinks" => Ok(ErrorKindVariant(ErrorKind::TooManyLinks)),
                    //"FilenameTooLong" => Ok(ErrorKindVariant(ErrorKind::FilenameTooLong)),
                    "ArgumentListTooLong" => Ok(ErrorKindVariant(ErrorKind::ArgumentListTooLong)),
                    "Interrupted" => Ok(ErrorKindVariant(ErrorKind::Interrupted)),
                    "Unsupported" => Ok(ErrorKindVariant(ErrorKind::Unsupported)),
                    "UnexpectedEof" => Ok(ErrorKindVariant(ErrorKind::UnexpectedEof)),
                    "OutOfMemory" => Ok(ErrorKindVariant(ErrorKind::OutOfMemory)),
                    "Other" => Ok(ErrorKindVariant(ErrorKind::Other)),
                    "Uncategorized" => Ok(ErrorKindVariant(ErrorKind::Uncategorized)),
                    _ => Err(SerdeError::unknown_variant(value, VARIANTS)),
                }
            }
        }
        impl<'de> Deserialize<'de> for ErrorKindVariant {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Deserializer::deserialize_identifier(deserializer, ErrorKindVariantVisitor)
            }
        }

        struct ErrorKindVisitor<'de> {
            marker: PhantomData<Error>,
            lifetime: PhantomData<&'de ()>,
        }

        impl<'de> Visitor<'de> for ErrorKindVisitor<'de> {
            type Value = ErrorKind;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                Formatter::write_str(formatter, "enum ErrorKind")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: EnumAccess<'de>,
            {
                match EnumAccess::variant(data)? {
                    (ErrorKindVariant(kind), val) => {
                        VariantAccess::unit_variant(val)?;
                        Ok(kind)
                    }
                }
            }
        }

        const VARIANTS: &'static [&'static str] =
            &["NotFound", "PermissionDenied", "ConnectionRefused", "ConnectionReset",
              "HostUnreachable", "NetworkUnreachable", "ConnectionAborted", "NotConnected",
              "AddrInUse", "AddrNotAvailable", "NetworkDown", "BrokenPipe",
              "AlreadyExists", "WouldBlock", "NotADirectory", "IsADirectory",
              "DirectoryNotEmpty", "ReadOnlyFilesystem", "FilesystemLoop", "StaleNetworkFileHandle",
              "InvalidInput", "InvalidData", "TimedOut", "WriteZero",
              "StorageFull", "NotSeekable", "FilesystemQuotaExceeded", "FileTooLarge",
              "ResourceBusy", "ExecutableFileBusy", "Deadlock", "CrossesDevices",
              "TooManyLinks", /*"FilenameTooLong",*/ "ArgumentListTooLong", "Interrupted",
              "Unsupported", "UnexpectedEof", "OutOfMemory", "Other",
              "Uncategorized"];

        Deserializer::deserialize_enum(
            deserializer,
            "ErrorKind",
            VARIANTS,
            ErrorKindVisitor {
                marker: PhantomData::<Error>,
                lifetime: PhantomData,
            },
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature="std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature="std", error("connection not found"))]
    ConnectionNotFound,
    #[cfg_attr(feature="std", error("system error {0}"))]
    SystemError(i32),
    #[cfg_attr(feature="std", error("unknown error"))]
    Unknown,
    #[cfg_attr(feature="std", error("vsock error"))]
    VsockError,
    /// Command executed on behalf of enclave (e.g., bind, accept, ...) resulted in an error. 
    ///   This error itself should be returned as the result of the command.
    #[cfg_attr(feature="std", error("enclave command error of kind {0:?}"))]
    Command(ErrorKind),
}

/// Serializes an `Error` value. We can't rely on the `serde` `Serialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
/// This implementation is based on the expanded `Serialize` macro.
#[cfg(feature="serde")]
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
            Error::Command(ref kind) =>
                Serializer::serialize_newtype_variant(serializer, "Error", 4u32, "Command", kind),
        }
    }
}

/// Deserializes an `Error` value. We can't rely on the `serde` `Deserialize` macro as we wish to use
/// this crate in the standard library.
/// See <https://github.com/rust-lang/rust/issues/64671>
#[cfg(feature="serde")]
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
            Command,
        }
        struct ErrorVariantVisitor;
        impl<'de> Visitor<'de> for ErrorVariantVisitor {
            type Value = ErrorVariant;

            fn expecting(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
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
                    "Command" => Ok(ErrorVariant::Command),
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
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
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
                    (ErrorVariant::Command, val) =>
                        VariantAccess::newtype_variant::<ErrorKind>(val).map(Error::Command),
                }
            }
        }

        const VARIANTS: &'static [&'static str] =
            &["ConnectionNotFound", "SystemError", "Unknown", "VsockError", "Command"];

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
    #[cfg(feature="std")]
    use {
        std::net::{IpAddr, SocketAddr},
        std::str::FromStr,
        std::string::String,
        std::vec::Vec,
        crate::{Addr, Error, ErrorKind, Response, Request},
    };

    #[test]
    #[cfg(any(feature="core", feature="std"))]
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
    #[cfg(feature="serde")]
    fn test_error_kind() {
        let data: Vec<(ErrorKind, Vec<u8>)> = Vec::from([
            (ErrorKind::NotFound,
                Vec::from([0x68, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64])),
            (ErrorKind::PermissionDenied,
                Vec::from([0x70, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x6e, 0x69, 0x65, 0x64])),
            (ErrorKind::ConnectionRefused,
                Vec::from([0x71, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64])),
            (ErrorKind::ConnectionReset,
                Vec::from([0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x65, 0x74])),
            (ErrorKind::HostUnreachable,
                Vec::from([0x6f, 0x48, 0x6f, 0x73, 0x74, 0x55, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65])),
            (ErrorKind::NetworkUnreachable,
                Vec::from([0x72, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x55, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65])),
            (ErrorKind::ConnectionAborted,
                Vec::from([0x71, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x65, 0x64])),
            (ErrorKind::NotConnected,
                Vec::from([0x6c, 0x4e, 0x6f, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64])),
            (ErrorKind::AddrInUse,
                Vec::from([0x69, 0x41, 0x64, 0x64, 0x72, 0x49, 0x6e, 0x55, 0x73, 0x65])),
            (ErrorKind::AddrNotAvailable,
                Vec::from([0x70, 0x41, 0x64, 0x64, 0x72, 0x4e, 0x6f, 0x74, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65])),
            (ErrorKind::NetworkDown,
                Vec::from([0x6b, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x44, 0x6f, 0x77, 0x6e])),
            (ErrorKind::BrokenPipe,
                Vec::from([0x6a, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x6e, 0x50, 0x69, 0x70, 0x65])),
            (ErrorKind::AlreadyExists,
                Vec::from([0x6d, 0x41, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x45, 0x78, 0x69, 0x73, 0x74, 0x73])),
            (ErrorKind::WouldBlock,
                Vec::from([0x6a, 0x57, 0x6f, 0x75, 0x6c, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b])),
            (ErrorKind::NotADirectory,
                Vec::from([0x6d, 0x4e, 0x6f, 0x74, 0x41, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79])),
            (ErrorKind::IsADirectory,
                Vec::from([0x6c, 0x49, 0x73, 0x41, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79])),
            (ErrorKind::DirectoryNotEmpty,
                Vec::from([0x71, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x4e, 0x6f, 0x74, 0x45, 0x6d, 0x70, 0x74, 0x79])),
            (ErrorKind::ReadOnlyFilesystem,
                Vec::from([0x72, 0x52, 0x65, 0x61, 0x64, 0x4f, 0x6e, 0x6c, 0x79, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d])),
            (ErrorKind::FilesystemLoop,
                Vec::from([0x6e, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x4c, 0x6f, 0x6f, 0x70])),
            (ErrorKind::StaleNetworkFileHandle,
                Vec::from([0x76, 0x53, 0x74, 0x61, 0x6c, 0x65, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x46, 0x69, 0x6c, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65])),
            (ErrorKind::InvalidInput,
                Vec::from([0x6c, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x49, 0x6e, 0x70, 0x75, 0x74])),
            (ErrorKind::InvalidData,
                Vec::from([0x6b, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x44, 0x61, 0x74, 0x61])),
            (ErrorKind::TimedOut,
                Vec::from([0x68, 0x54, 0x69, 0x6d, 0x65, 0x64, 0x4f, 0x75, 0x74])),
            (ErrorKind::WriteZero,
                Vec::from([0x69, 0x57, 0x72, 0x69, 0x74, 0x65, 0x5a, 0x65, 0x72, 0x6f])),
            (ErrorKind::StorageFull,
                Vec::from([0x6b, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x46, 0x75, 0x6c, 0x6c])),
            (ErrorKind::NotSeekable,
                Vec::from([0x6b, 0x4e, 0x6f, 0x74, 0x53, 0x65, 0x65, 0x6b, 0x61, 0x62, 0x6c, 0x65])),
            (ErrorKind::FilesystemQuotaExceeded,
                Vec::from([0x77, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x51, 0x75, 0x6f, 0x74, 0x61, 0x45, 0x78, 0x63, 0x65, 0x65, 0x64, 0x65, 0x64])),
            (ErrorKind::FileTooLarge,
                Vec::from([0x6c, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x6f, 0x6f, 0x4c, 0x61, 0x72, 0x67, 0x65])),
            (ErrorKind::ResourceBusy,
                Vec::from([0x6c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x42, 0x75, 0x73, 0x79])),
            (ErrorKind::ExecutableFileBusy,
                Vec::from([0x72, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x42, 0x75, 0x73, 0x79])),
            (ErrorKind::Deadlock,
                Vec::from([0x68, 0x44, 0x65, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b])),
            (ErrorKind::CrossesDevices,
                Vec::from([0x6e, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x65, 0x73, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73])),
            (ErrorKind::TooManyLinks,
                Vec::from([0x6c, 0x54, 0x6f, 0x6f, 0x4d, 0x61, 0x6e, 0x79, 0x4c, 0x69, 0x6e, 0x6b, 0x73])),
            //(ErrorKind::FilenameTooLong,
            //    Vec::from([0x6f, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x54, 0x6f, 0x6f, 0x4c, 0x6f, 0x6e, 0x67])),
            (ErrorKind::ArgumentListTooLong,
                Vec::from([0x73, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x54, 0x6f, 0x6f, 0x4c, 0x6f, 0x6e, 0x67])),
            (ErrorKind::Interrupted,
                Vec::from([0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70, 0x74, 0x65, 0x64])),
            (ErrorKind::Unsupported,
                Vec::from([0x6b, 0x55, 0x6e, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64])),
            (ErrorKind::UnexpectedEof,
                Vec::from([0x6d, 0x55, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x45, 0x6f, 0x66])),
            (ErrorKind::OutOfMemory,
                Vec::from([0x6b, 0x4f, 0x75, 0x74, 0x4f, 0x66, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79])),
            (ErrorKind::Other,
                Vec::from([0x65, 0x4f, 0x74, 0x68, 0x65, 0x72])),
            (ErrorKind::Uncategorized,
                Vec::from([0x6d, 0x55, 0x6e, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64])),
        ]);

        for (errk, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(&errk).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<ErrorKind>(&bin).unwrap(), *errk);
        }
    }

    #[test]
    #[cfg(feature="serde")]
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
            (Error::Command(ErrorKind::NotFound),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x68, 0x4e, 0x6f, 0x74, 0x46, 0x6f, 0x75, 0x6e, 0x64])),
            (Error::Command(ErrorKind::PermissionDenied),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x70, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x44, 0x65, 0x6e, 0x69, 0x65, 0x64])),
            (Error::Command(ErrorKind::ConnectionRefused),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x71, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64])),
            (Error::Command(ErrorKind::ConnectionReset),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x65, 0x74])),
            (Error::Command(ErrorKind::HostUnreachable),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x48, 0x6f, 0x73, 0x74, 0x55, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65])),
            (Error::Command(ErrorKind::NetworkUnreachable),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x72, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x55, 0x6e, 0x72, 0x65, 0x61, 0x63, 0x68, 0x61, 0x62, 0x6c, 0x65])),
            (Error::Command(ErrorKind::ConnectionAborted),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x71, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x62, 0x6f, 0x72, 0x74, 0x65, 0x64])),
            (Error::Command(ErrorKind::NotConnected),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x4e, 0x6f, 0x74, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64])),
            (Error::Command(ErrorKind::AddrInUse),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x69, 0x41, 0x64, 0x64, 0x72, 0x49, 0x6e, 0x55, 0x73, 0x65])),
            (Error::Command(ErrorKind::AddrNotAvailable),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x70, 0x41, 0x64, 0x64, 0x72, 0x4e, 0x6f, 0x74, 0x41, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65])),
            (Error::Command(ErrorKind::NetworkDown),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x44, 0x6f, 0x77, 0x6e])),
            (Error::Command(ErrorKind::BrokenPipe),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6a, 0x42, 0x72, 0x6f, 0x6b, 0x65, 0x6e, 0x50, 0x69, 0x70, 0x65])),
            (Error::Command(ErrorKind::AlreadyExists),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6d, 0x41, 0x6c, 0x72, 0x65, 0x61, 0x64, 0x79, 0x45, 0x78, 0x69, 0x73, 0x74, 0x73])),
            (Error::Command(ErrorKind::WouldBlock),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6a, 0x57, 0x6f, 0x75, 0x6c, 0x64, 0x42, 0x6c, 0x6f, 0x63, 0x6b])),
            (Error::Command(ErrorKind::NotADirectory),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6d, 0x4e, 0x6f, 0x74, 0x41, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79])),
            (Error::Command(ErrorKind::IsADirectory),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x49, 0x73, 0x41, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79])),
            (Error::Command(ErrorKind::DirectoryNotEmpty),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x71, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x4e, 0x6f, 0x74, 0x45, 0x6d, 0x70, 0x74, 0x79])),
            (Error::Command(ErrorKind::ReadOnlyFilesystem),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x72, 0x52, 0x65, 0x61, 0x64, 0x4f, 0x6e, 0x6c, 0x79, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d])),
            (Error::Command(ErrorKind::FilesystemLoop),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6e, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x4c, 0x6f, 0x6f, 0x70])),
            (Error::Command(ErrorKind::StaleNetworkFileHandle),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x76, 0x53, 0x74, 0x61, 0x6c, 0x65, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x46, 0x69, 0x6c, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65])),
            (Error::Command(ErrorKind::InvalidInput),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x49, 0x6e, 0x70, 0x75, 0x74])),
            (Error::Command(ErrorKind::InvalidData),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x49, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x44, 0x61, 0x74, 0x61])),
            (Error::Command(ErrorKind::TimedOut),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x64, 0x4f, 0x75, 0x74])),
            (Error::Command(ErrorKind::WriteZero),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x69, 0x57, 0x72, 0x69, 0x74, 0x65, 0x5a, 0x65, 0x72, 0x6f])),
            (Error::Command(ErrorKind::StorageFull),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x46, 0x75, 0x6c, 0x6c])),
            (Error::Command(ErrorKind::NotSeekable),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x4e, 0x6f, 0x74, 0x53, 0x65, 0x65, 0x6b, 0x61, 0x62, 0x6c, 0x65])),
            (Error::Command(ErrorKind::FilesystemQuotaExceeded),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x77, 0x46, 0x69, 0x6c, 0x65, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x51, 0x75, 0x6f, 0x74, 0x61, 0x45, 0x78, 0x63, 0x65, 0x65, 0x64, 0x65, 0x64])),
            (Error::Command(ErrorKind::FileTooLarge),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x6f, 0x6f, 0x4c, 0x61, 0x72, 0x67, 0x65])),
            (Error::Command(ErrorKind::ResourceBusy),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x42, 0x75, 0x73, 0x79])),
            (Error::Command(ErrorKind::ExecutableFileBusy),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x72, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x42, 0x75, 0x73, 0x79])),
            (Error::Command(ErrorKind::Deadlock),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x68, 0x44, 0x65, 0x61, 0x64, 0x6c, 0x6f, 0x63, 0x6b])),
            (Error::Command(ErrorKind::CrossesDevices),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6e, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x65, 0x73, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73])),
            (Error::Command(ErrorKind::TooManyLinks),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6c, 0x54, 0x6f, 0x6f, 0x4d, 0x61, 0x6e, 0x79, 0x4c, 0x69, 0x6e, 0x6b, 0x73])),
            //(Error::Command(ErrorKind::FilenameTooLong),
            //    Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6f, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x54, 0x6f, 0x6f, 0x4c, 0x6f, 0x6e, 0x67])),
            (Error::Command(ErrorKind::ArgumentListTooLong),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x73, 0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x54, 0x6f, 0x6f, 0x4c, 0x6f, 0x6e, 0x67])),
            (Error::Command(ErrorKind::Interrupted),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x72, 0x75, 0x70, 0x74, 0x65, 0x64])),
            (Error::Command(ErrorKind::Unsupported),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x55, 0x6e, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64])),
            (Error::Command(ErrorKind::UnexpectedEof),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6d, 0x55, 0x6e, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x45, 0x6f, 0x66])),
            (Error::Command(ErrorKind::OutOfMemory),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6b, 0x4f, 0x75, 0x74, 0x4f, 0x66, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79])),
            (Error::Command(ErrorKind::Other),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x65, 0x4f, 0x74, 0x68, 0x65, 0x72])),
            (Error::Command(ErrorKind::Uncategorized),
                Vec::from([0xa1, 0x67, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x6d, 0x55, 0x6e, 0x63, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64])),
        ]);

        for (err, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(&err).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Error>(&bin).unwrap(), *err);
        }
    }

    #[test]
    #[cfg(feature="serde")]
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
    #[cfg(feature="serde")]
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
            (
                Request::Exit {
                    code: 0,
                },
                Vec::from([
                    0xa1, 0x64, 0x45, 0x78, 0x69, 0x74, 0xa1, 0x64, 0x63, 0x6f, 0x64, 0x65, 0x00
                ]),
            ),
            (
                Request::Exit {
                    code: 42,
                },
                Vec::from([
                    0xa1, 0x64, 0x45, 0x78, 0x69, 0x74, 0xa1, 0x64, 0x63, 0x6f, 0x64, 0x65, 0x18,
                    0x2a
                ]),
            ),
            (
                Request::Init,
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x69, 0x74, 0xa0,
                ]),
            ),
        ]);

        for (req, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(&req).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Request>(&bin).unwrap(), *req);
        }
    }

    #[test]
    #[cfg(feature="serde")]
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
            (
                Response::Init {
                    args: Vec::new(),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x69, 0x74, 0xa1, 0x64, 0x61, 0x72, 0x67, 0x73, 0x80,
                ]),
            ),
            (
                Response::Init {
                    args: Vec::from([String::from("arg0")]),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x69, 0x74, 0xa1, 0x64, 0x61, 0x72, 0x67, 0x73, 0x81,
                    0x64, 0x61, 0x72, 0x67, 0x30
                ]),
            ),
            (
                Response::Init {
                    args: Vec::from([String::from("arg0"), String::from("arg1")]),
                },
                Vec::from([
                    0xa1, 0x64, 0x49, 0x6e, 0x69, 0x74, 0xa1, 0x64, 0x61, 0x72, 0x67, 0x73, 0x82,
                    0x64, 0x61, 0x72, 0x67, 0x30, 0x64, 0x61, 0x72, 0x67, 0x31
                ]),
            ),
        ]);

        for (resp, bin) in data.iter() {
            assert_eq!(serde_cbor::ser::to_vec(resp).unwrap(), *bin);
            assert_eq!(serde_cbor::de::from_slice::<Response>(&bin).unwrap(), *resp);
        }
    }
}
