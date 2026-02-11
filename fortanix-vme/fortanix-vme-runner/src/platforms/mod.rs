use crate::RunnerError;

pub(crate) mod amdsevsnp;

mod nitro;
pub use nitro::NitroEnclaves;

mod enclave_simulator;
pub use enclave_simulator::{EnclaveSimulator, EnclaveSimulatorArgs};

pub trait Platform: Send + Sync {
    type RunArgs: Send;
    type EnclaveDescriptor: Send + Sync;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError>;
}
