//! The Fortanix VME ABI (compiler target `x86_64-unknown-linux-fortanixvme`) 
//! is an interface for VM-based enclaves. It is a small yet functional 
//! interface suitable for writing larger enclaves. In contrast to other 
//! enclave interfaces, this interface is primarly designed for running entire 
//! applications in an enclave.
//!
//! The Fortanix VME ABI specification consists of two parts:
//!
//! 1. The serialization format
//! 2. The execution environment and host services
//!
//! Whereas the serialization format describes how information is passed to and 
//! from the enclave, the rest of this document ascribes meaning to that 
//! information.
//!
//! The execution environment and host services have been designed with the 
//! following goals in mind:
//!
//! 1. *Compatible with most Rust code:* Rust code that doesn’t link to other C 
//! libraries and that doesn’t use files (see no. 5) should compile out of the 
//! box.
//! 2. *Designed for single-application VM-based enclaves*: Following the 
//! design principles of Intel SGX and the Fortanix SGX ABI, this environment 
//! is designed to make it hard to do the wrong thing from a security 
//! perspective. The primitives specified in this document are designed to work 
//! well for high-assurance security software, not to be similar to or 
//! compatible with primitives known from other environments.
//! 3. *Designed for network services:* The most interesting usecase for VM-based 
//! enclaves is to run applications remotely in an untrusted environment, e.g. 
//! the cloud. Therefore, there is a primary focus on supporting functionality 
//! needed in those situations.
//! 4. *No filesystem:* Encrypted filesystems are hard. Especially in secure 
//! enclaves, consistency and freshness are big concerns. In this initial 
//! version, there is no filesystem support, which is fine for most network 
//! services, which would want to keep their state with a database service 
//! anyway. Support might be added in the future.
//! 5. *Not POSIX:* The POSIX API is huge and contains many elements that are 
//! not needed for most use cases. It is explicitly a non-goal of this 
//! specification to support all of POSIX. This also ensures compatibility with 
//! the Fortanix SGX ABI.
//! 6. *Designed to be portable:* Enclaves don’t interact directly with the OS, 
//! so there should be no need to recompile an enclave when running it with a 
//! different OS. This specification does not require any particular primitives 
//! or behavior from the OS.
//!
//! # Virtio socket device (vsock)
//!
//! The only communication between a VM enclave and the host is via the virtio 
//! socket device (vsock). Any interface offered through this mechanism is
//! called a service. The details for each service can be found in [`services`].

/// A vsock CID
pub type Cid = u32;

/// A vsock port
pub type Port = u32;

/// A vsock port offset.
///
/// See [`host_discovery`] on how to determine the port base.
pub type PortOffset = u32;

/// TODO
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

pub mod host_discovery {
    // NOTE: Throughout this file, module documentation is done using an
    // inner-doc-comment, so that the namespace for rustdoc automatic item
    // linking is correct.
    //! Methods for an enclave to discover how to connect to host services
    //!
    //! In order for the enclave to setup a vsock connection to a host service, 
    //! it needs to know the destination CID and port. [`HOST_CID`] determines 
    //! the destination CID. The destination port can be determined by adding 
    //! the port offset for the specific host service to the port base. Each 
    //! host service definition has a `PORT_OFFSET` constant of type that can 
    //! be used for this purpose.
    //!
    //! The port base is the guest CID.
    //!
    //! This discovery mechanism is chosen for compatibility with AWS Nitro 
    //! Enclaves, but is also suitable for bare-metal VMs. Future updates to this
    //! specification may define new discovery mechanisms for other platforms.

    pub const HOST_CID: crate::Cid = 3;
}

pub mod services {
    //! VME service definitions
    //!
    //! A VME service is characterized by vsock listening sockets that serve a 
    //! singular purpose. By using separate streams, multiplexing of concurrent 
    //! operations comes standard, and asynchronous implementations are 
    //! obvious. It's also easier to map data-carrying streams one-to-one. This 
    //! includes mapping error conditions and signaling.
    //!
    //! If the listening socket is on the host, this is called a host service. 
    //! If it's on the enclave, it's an enclave service.
    //!
    //! # Networking
    //!
    //! In keeping with the design goals for this specification, the 
    //! networking/socket interface doesn't use `sockaddr` types and doesn't 
    //! have a separate API for name resolution. The hypervisor can't be 
    //! trusted to do name resolution correctly, and even if it did, *the 
    //! hypervisor can't be trusted to actually connect streams to the correct 
    //! address* specified by the enclave. Therefore, addresses specified 
    //! should merely be treated as a suggestion, and additional measures must 
    //! be taken by an enclave to verify the stream is connected to the correct 
    //! peer, e.g. TLS.
    //!
    //! The networking API works with strings as addresses. All byte buffers 
    //! representing network addresses should contain a valid UTF-8 string. The 
    //! enclave should panic if it is passed an invalid string by the 
    //! hypervisor. It is suggested that the hypervisor supports at least the 
    //! following notations:
    //!
    //! * `hostname:port-number` (e.g. `example.com:123`)
    //! * `dotted-octet-ipv4-address:port-number` (e.g. `192.0.2.1:123`)
    //! * `[ipv6-address]:port-number` (e.g. `[2001:db8::1]:123`)
    //!
    //! Additionally, other forms may be accepted, for example service names:
    //!
    //! * `fully-qualified-service-name` (e.g. `_example._tcp.example.com`)
    //! * `address:service-name` (e.g. `address:example`)
    //!
    //! # Errors
    //!
    //! Networking calls taking an address may return the [`InvalidInput`] 
    //! error if the address could not be interpreted by the hypervisor.
    //!
    //! [`InvalidInput`]: enum.Error.html#variant.InvalidInput

    /// A representation of local and peer addresses for a stream connection.
    ///
    /// The enclave must not make any security decisions based on the local or 
    /// peer address received.
    ///
    /// See [`services`](crate::services) for more information on addressing.
    pub struct ConnectionData {
        pub local_addr: String,
        pub peer_addr: String,
    }

    pub mod host {
        //! VME host service definitions
        //! 
        //! In addition to some basic facilities, a VM enclave is able to 
        //! request that the host setup byte-stream (network) connections on 
        //! its behalf. The actual stream data is always communicated via the 
        //! vsock. Each external stream maps 1-to-1 to a vsock stream.
        //!
        //! See [`host_discovery`](crate::host_discovery) for how enclaves can
        //! determine how to connect to these services.
        pub mod control {
            //! The `control` service controls enclave execution.
            //!
            //! Upon startup, the enclave should connect to the service 
            //! immediately. It should keep the connection open for as long as the 
            //! enclave runs. The host should terminate the enclave if the 
            //! connection is closed by the enclave.
            //!
            //! The host must send the [`Init`] message immediately 
            //! after accepting the connection.
            //!
            //! The enclave must send the [`Exit`] message if it 
            //! wishes to terminate gracefully. If the host terminates the enclave
            //! non-gracefully for any reason, it will represent this with a
            //! non-zero exit code.
            //! 
            //! Only one connect request per enclave should be made on this service.
 
            pub const PORT_OFFSET: crate::PortOffset = 0;

            /// Communicate initialization data to the enclave.
            ///
            /// The enclave must not make any security decisions based on this 
            /// input.
            pub struct Init {
                /// Arbitrary “command-line arguments” may be passed in by the 
                /// host.
                pub args: Vec<String>,
            }

            /// Request enclave termination.
            ///
            /// The host may terminate the enclave immediately upon receiving
            /// this message. If the enclave wishes to perform any cleanup, it
            /// must do so before sending this message.
            pub struct Exit {
                pub code: i32,
            }
        }

        pub mod connect {
            //! Create a new stream connection to the specified address.
            //!
            //! The enclave must send the [`ConnectRequest`] message 
            //! immediately after creating the connection.
            //!
            //! The host will always respond with a [`ConnectResponse`] 
            //! message. 
            //!
            //! After that message, if success was indicated, all other data on 
            //! the stream will be forwarded verbatim in both directions 
            //! between the enclave and the peer. If an error was indicated, 
            //! the connection must be closed.
            pub const PORT_OFFSET: crate::PortOffset = 1;

            pub struct ConnectRequest {
                /// The destination address.
                ///
                /// See [`services`](crate::services) for more information on
                /// addressing.
                pub addr: String,
            }

            pub type ConnectResponse = crate::Result<crate::services::ConnectionData>;
        }
        


        pub mod bind {
            //! Setup a listening socket.
            //!
            //! The enclave must send the [`BindRequest`] message 
            //! immediately after creating the connection.
            //!
            //! The host will always respond with a [`BindResponse`] message. 
            //!
            //! After that message, if success was indicated, the host 
            //! associate this connection to the `bind` service with that 
            //! socket. No further data will be communicated on this 
            //! connection. The host will forward incoming connections on the 
            //! listening socket to the [`accept` enclave 
            //! service](crate::services::enclave::accept) specified in the 
            //! request for as long as this associated connection remains open. 
            //!
            //! If an error was indicated in the `BindResponse`, the connection 
            //! must be closed immediately.
            //!
            //! If the host encounters a non-recoverable error on the listening 
            //! socket, for example while trying to accept a connection, the 
            //! host must close the associated connection immediately, 
            //! indicating to the enclave that the listening socket can no 
            //! longer be used.
            //!
            //! Once either side initiates termination of the associated 
            //! connection, the host must no longer forward incoming 
            //! connections to the enclave service.
            pub const PORT_OFFSET: crate::PortOffset = 2;

            pub struct BindRequest {
                /// The address to listen on.
                ///
                /// See [`services`](crate::services) for more information on
                /// addressing.
                pub addr: String,
                pub port: crate::Port,
            }

            pub struct BindData {
                /// A representation of the local address for a listening 
                /// socket.
                ///
                /// The enclave must not make any security decisions based on 
                /// the address received.
                ///
                /// See [`services`](crate::services) for more information on 
                /// addressing.
                pub local_addr: String,
            }

            pub type BindResponse = crate::Result<BindData>;
        }
        
        pub mod stdin {
            //! Standard input service.
            //! 
            //! Upon startup, the enclave should connect to the service 
            //! immediately. 
            //! 
            //! The host may forward any “standard input” data on this 
            //! connection. Input read this way is not secure. The enclave 
            //! shouldn't send any data on this connection.
            //! 
            //! Only one connect request per enclave should be made on this 
            //! service

            pub const PORT_OFFSET: crate::PortOffset = 3;
        }
        
        pub mod stdout {
            //! Standard output service.
            //! 
            //! Upon startup, the enclave should connect to the service 
            //! immediately. 
            //! 
            //! The enclave may forward any “standard output” data on this 
            //! connection. This is not a secure output channel. The host 
            //! shouldn't send any data on this connection.
            //! 
            //! Only one connect request per enclave should be made on this 
            //! service

            pub const PORT_OFFSET: crate::PortOffset = 4;
        }
        
        pub mod stderr {
            //! Standard error service.
            //! 
            //! Upon startup, the enclave should connect to the service 
            //! immediately. 
            //! 
            //! The enclave may forward any “standard error” data on this 
            //! connection. This is not a secure output channel. The host 
            //! shouldn't send any data on this connection.
            //! 
            //! Only one connect request per enclave should be made on this 
            //! service

            pub const PORT_OFFSET: crate::PortOffset = 5;
        }
    }
    
    pub mod enclave {
        //! VME enclave service definitions
        //!
        //! Enclave services don't have a fixed addressing scheme. The enclave
        //! must use the available host services to communicate to the host
        //! which enclave services are available and where.
        
        pub mod accept {
            //! Accept a new stream connection on a listening socket.
            //!
            //! The host must send the [`Accept`] message immediately after 
            //! creating the connection.
            //!
            //! After that message, all other data on the stream will be 
            //! forwarded verbatim in both directions between the enclave and 
            //! the peer.

            pub type Accept = crate::services::ConnectionData;
        }
    }
}
