use super::VmeError;

pub(crate) mod amdsev;

mod nitro;
pub use nitro::NitroEnclaves;

mod enclave_simulator;
pub use enclave_simulator::{EnclaveSimulator, EnclaveSimulatorArgs};

pub trait Platform: Send + Sync {
    type RunArgs;
    type EnclaveDescriptor: Send + Sync;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, VmeError>;
}
