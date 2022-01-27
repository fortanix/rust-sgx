#![deny(warnings)]
#![no_std]
extern crate alloc;
#[cfg(feature="std")]
extern crate std;

use alloc::string::String;
use core::fmt::{self, Formatter};
use core::marker::PhantomData;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{EnumAccess, Error as SerdeError, Unexpected, VariantAccess, Visitor};

#[cfg(feature="std")]
use {
    std::io,
    std::net::SocketAddr,
    vsock::Error as VsockError,
};

pub const SERVER_PORT: u32 = 10000;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    use std::vec::Vec;
    use crate::{Addr, Error};

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
}
