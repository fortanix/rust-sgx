use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use nix::Error;
use std::borrow::Cow;
use std::{
    ffi::c_int,
    path::PathBuf,
    process::{Child, Command},
};

use crate::RunnerError;

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

struct VmRuntime {
    guest_fd: c_int,
    guest_cid: u64,
}

pub struct AmdSevVm;
/// Warning: unprotected VM for use on DEV machines only
pub struct VmSimulator;

pub struct RunningVm {
    child: Child,
    runtime: VmRuntime,
}

enum RunMode {
    AmdSevVm,
    VmSimulator,
}

fn map_nix_error<I: Into<Cow<'static, str>>>(msg: I, err: Error) -> RunnerError {
    RunnerError::Io(Some(msg.into()), err.into())
}

// Define the VHOST_VSOCK_SET_GUEST_CID ioctl
// In C: _IOW(VHOST_VIRTIO, 0x60, __u64)
const VHOST_VIRTIO: u8 = 0xAF;
const VHOST_VSOCK_DEV: &str = "/dev/vhost-vsock";
nix::ioctl_write_ptr!(set_guest_cid, VHOST_VIRTIO, 0x60, u64);

// This function basically opens vhost-vsock device and
// tries to allocate a cid number. If allocation succeeds
// we simply re-use it along with the file descriptor.
fn get_available_guest_cid_with_fd() -> Result<(c_int, u64), RunnerError> {
    for mut cid in 3u64..=64 {
        unsafe {
            // We're deliberately omitting O_CLOEXEC here as we want
            // the child process inherit the opened file descriptors.
            let fd = open(VHOST_VSOCK_DEV, OFlag::O_RDWR, Mode::empty()).map_err(|e| {
                map_nix_error(
                    format!("Unable to open vhost-vsock device: {}", VHOST_VSOCK_DEV),
                    e,
                )
            })?;
            let res = set_guest_cid(fd, &mut cid);
            match res {
                Ok(_) => return Ok((fd, cid)),
                Err(err_code) => {
                    let _ = close(fd);
                    if err_code == nix::Error::EADDRINUSE {
                        continue;
                    }

                    return Err(map_nix_error(
                        format!("Unable to ioctl vhost-vsock device: {}", VHOST_VSOCK_DEV),
                        err_code,
                    ));
                }
            }
        }
    }

    Err(RunnerError::Runtime(
        format!(
            "Unable to find available cid for guest vm (vhost-vsock device: {})",
            VHOST_VSOCK_DEV
        )
        .into(),
    ))
}

fn create_runtime_env() -> Result<VmRuntime, RunnerError> {
    let (guest_fd, guest_cid) = get_available_guest_cid_with_fd()?;
    Ok(VmRuntime {
        guest_fd,
        guest_cid,
    })
}

fn build_qemu_command(
    run_mode: RunMode,
    vm_run_args: VmRunArgs,
    vm_runtime: &VmRuntime,
) -> Command {
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
        .arg(&memory_size)
        .arg("-device")
        .arg(format!(
            "vhost-vsock-pci,id=vhost-vsock-pci0,vhostfd={},guest-cid={}",
            vm_runtime.guest_fd, vm_runtime.guest_cid
        ));

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

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let runtime = create_runtime_env()?;
        let child = build_qemu_command(RunMode::AmdSevVm, run_args.into(), &runtime)
            .spawn()
            .map_err(|e| (e, "failed to spawn amd sev snp vm through qemu"))?;
        Ok(RunningVm { child, runtime })
    }
}

impl Platform for VmSimulator {
    type RunArgs = VmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let runtime = create_runtime_env()?;
        let child = build_qemu_command(RunMode::VmSimulator, run_args.into(), &runtime)
            .spawn()
            .map_err(|e| (e, "failed to spawn vm through qemu"))?;
        Ok(RunningVm { child, runtime })
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Close the fd opened for the guest vm vsock support
        let _ = close(self.runtime.guest_fd);
    }
}
