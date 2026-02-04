use super::Platform;
use crate::RunnerError;
use std::path::PathBuf;
use std::process::{Child, Command};

pub struct EnclaveSimulator;
pub struct EnclaveSimulatorArgs {
    enclave_path: PathBuf,
}

impl EnclaveSimulatorArgs {
    pub fn new(enclave_path: PathBuf) -> Self {
        EnclaveSimulatorArgs { enclave_path }
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

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let enclave = Command::new(run_args.into().enclave_path).spawn()?;
        Ok(RunningSimulator::new(enclave))
    }
}
