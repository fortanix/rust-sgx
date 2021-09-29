#[cfg(feature = "sgx")]
pub mod sgx;

#[cfg(feature = "sgx")]
pub use sgx::get_remote_attestation_parameters;

#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "nitro")]
pub use nitro::get_remote_attestation_parameters;
