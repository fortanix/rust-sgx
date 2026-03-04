use crate::RunnerError;
use std::process::ExitStatus;

pub(crate) mod amdsevsnp;

mod nitro;
pub use nitro::NitroEnclaves;

mod enclave_simulator;
pub use enclave_simulator::{EnclaveSimulator, EnclaveSimulatorArgs};

pub trait Platform: Send + Sync {
    type RunArgs;
    type EnclaveDescriptor: EnclaveRuntime + Send + Sync;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError>;
}

pub trait EnclaveRuntime {
    async fn wait(&mut self) -> Result<ExitStatus, RunnerError>;
}
