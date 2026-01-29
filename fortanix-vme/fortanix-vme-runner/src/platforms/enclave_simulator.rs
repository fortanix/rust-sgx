use crate::VmeError;
use std::path::PathBuf;
use std::process::{Child, Command};
use super::Platform;

pub struct EnclaveSimulator;
pub struct EnclaveSimulatorArgs {
    enclave_path: PathBuf,
}

impl EnclaveSimulatorArgs {
    pub fn new(enclave_path: PathBuf) -> Self {
        EnclaveSimulatorArgs {
            enclave_path
        }
    }
}

pub struct RunningSimulator(Child);

impl RunningSimulator {
    pub fn new(process: Child) -> Self {
        RunningSimulator(process)
    }
}

impl Drop for RunningSimulator {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

impl Platform for EnclaveSimulator {
    type RunArgs = EnclaveSimulatorArgs;
    type EnclaveDescriptor = RunningSimulator;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, VmeError> {
        let enclave = Command::new(run_args.into().enclave_path)
            .spawn()
            .expect("Running enclave as simulated process failed");
        Ok(RunningSimulator::new(enclave))
    }
}
