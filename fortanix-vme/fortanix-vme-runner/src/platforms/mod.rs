use super::VmeError;

mod nitro;
pub use nitro::NitroEnclaves;

mod simulator;
pub use simulator::{Simulator, SimulatorArgs};

pub trait Platform: Send + Sync {
    type RunArgs;
    type EnclaveDescriptor: Send + Sync;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, VmeError>;
}
