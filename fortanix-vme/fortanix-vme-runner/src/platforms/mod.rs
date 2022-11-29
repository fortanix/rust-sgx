use super::VmeError;

mod nitro;
pub use nitro::NitroEnclaves;

pub trait Platform: Send + Sync {
    type RunArgs;
    type EnclaveDescriptor;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, VmeError>;
    fn terminate(enclave: &Self::EnclaveDescriptor) -> Result<(), VmeError>;
}
