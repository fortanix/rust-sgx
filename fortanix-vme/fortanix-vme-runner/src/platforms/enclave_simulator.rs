use super::Platform;
use crate::platforms::EnclaveRuntime;
use crate::RunnerError;
use std::path::PathBuf;
use tokio::process::{Child, Command};

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

impl EnclaveRuntime for RunningSimulator {
    async fn wait(&mut self) -> Result<(), RunnerError> {
        let status = self.0.wait().await?;
        if !status.success() {
            return Err(RunnerError::PlatformCommandError(status));
        }

        Ok(())
    }
}

impl Platform for EnclaveSimulator {
    type RunArgs = EnclaveSimulatorArgs;
    type EnclaveDescriptor = RunningSimulator;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        // We're relying on tokio's runtime to stop or reap dead children
        // by specifying `kill_on_drop(true)` which would take place when
        // EnclaveDescriptor is dropped.
        let enclave = Command::new(run_args.into().enclave_path)
            .kill_on_drop(true)
            .spawn()?;
        Ok(RunningSimulator::new(enclave))
    }
}
