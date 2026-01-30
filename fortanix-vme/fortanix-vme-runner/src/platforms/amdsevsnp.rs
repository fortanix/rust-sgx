use std::{
    path::PathBuf,
    process::{Child, Command},
};

use super::Platform;

/// The arguments used by the `run-enclave` command.
#[derive(Debug)]
pub struct VmRunArgs {
    /// The path to the VM image file.
    pub uki_path: PathBuf,
    /// The path to the enclave image file.
    pub firmware_image_path: PathBuf,
    /// The amount of memory that will be given to the enclave.
    pub memory_mib: u64,
    /// The number of CPUs that the enclave will receive.
    pub cpu_count: u32,
}

pub struct AmdSevVm;
/// Warning: unprotected VM for use on DEV machines only
pub struct VmSimulator;

pub struct RunningVm(Child);

enum RunMode {
    AmdSevVm,
    VmSimulator,
}

fn build_qemu_command(run_mode: RunMode, vm_run_args: VmRunArgs) -> Command {
    const QEMU_EXECUTABLE: &str = "qemu-system-x86_64";
    const QEMU_MACHINE: &str = "q35";
    const AMD_PROCESSOR: &str = "EPYC-v4";

    let VmRunArgs {
        uki_path,
        firmware_image_path,
        memory_mib,
        cpu_count,
    } = vm_run_args;
    let memory_size = format!("{}M", memory_mib);

    // TODO (RTE-740): id-block
    let mut command = match run_mode {
        RunMode::AmdSevVm => {
            let mut command = Command::new("sudo");
            command.arg(QEMU_EXECUTABLE);
            command
        }
        RunMode::VmSimulator => Command::new(QEMU_EXECUTABLE),
    };

    // General machine setup
    // TODO: consider `no-defaults` option for devices
    command
        .arg("-enable-kvm")
        .arg("-nographic")
        .arg("-no-reboot")
        .arg("-smp")
        .arg(format!("cpus=1,maxcpus={}", cpu_count)) // TODO(RTE-745): hotplug these
        .arg("-machine")
        .arg(format!("{},vmport=off", QEMU_MACHINE))
        .arg("-m")
        .arg(&memory_size);

    // CPU
    command.arg("-cpu").arg(match run_mode {
        RunMode::AmdSevVm => AMD_PROCESSOR,
        RunMode::VmSimulator => "host",
    });

    // Memory
    command.arg("-machine").arg("memory-backend=ram1");
    command.arg("-object").arg(format!(
        "memory-backend-memfd,id=ram1,share=true,size={}",
        memory_size
    ));

    // Images
    command.arg("-kernel").arg(uki_path);
    command.arg("-bios").arg(firmware_image_path);

    if let RunMode::AmdSevVm = run_mode {
        command
            .arg("-machine")
            .arg("confidential-guest-support=sev0");
        command
            .arg("-object")
            .arg("sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on");
    }

    command
}

impl Platform for AmdSevVm {
    type RunArgs = VmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(
        run_args: I,
    ) -> Result<Self::EnclaveDescriptor, fortanix_vme_abi::Error> {
        let child = build_qemu_command(RunMode::AmdSevVm, run_args.into())
            .spawn()
            .expect("failed to run amd sev VM");
        Ok(RunningVm(child))
    }
}

impl Platform for VmSimulator {
    type RunArgs = VmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(
        run_args: I,
    ) -> Result<Self::EnclaveDescriptor, fortanix_vme_abi::Error> {
        let child = build_qemu_command(RunMode::VmSimulator, run_args.into())
            .spawn()
            .expect("failed to run simulated VM");
        Ok(RunningVm(child))
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}
