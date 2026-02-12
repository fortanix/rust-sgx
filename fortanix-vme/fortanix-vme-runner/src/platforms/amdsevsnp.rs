use log::{debug, info};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use nix::Error;
use std::borrow::Cow;
use std::os::fd::{AsRawFd, OwnedFd};
use std::{
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

pub struct AmdSevVm;
/// Warning: unprotected VM for use on DEV machines only
pub struct VmSimulator;

pub struct RunningVm {
    child: Child,
    // Field kept so that file descriptor is closed at the right time
    _vsock_config: VsockConfig,
}

struct VsockConfig {
    guest_fd: OwnedFd,
    guest_cid: u64,
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

// Port numbers below 1024 are called privileged ports.
const CID_START: u64 = 1024;

// This function basically opens vhost-vsock device and
// tries to allocate a cid number. If allocation succeeds
// we simply re-use it along with the file descriptor.
fn get_available_guest_cid_with_fd() -> Result<VsockConfig, RunnerError> {
    let mut cid = CID_START;
    loop {
        // We're deliberately omitting O_CLOEXEC here as we want
        // the child process inherit the opened file descriptors.
        let fd = open(VHOST_VSOCK_DEV, OFlag::O_RDWR, Mode::empty()).map_err(|e| {
            map_nix_error(
                format!("Unable to open vhost-vsock device: {}", VHOST_VSOCK_DEV),
                e,
            )
        })?;
        info!("opened vsock device under fd {}", fd.as_raw_fd());
        let res = unsafe { set_guest_cid(fd.as_raw_fd(), &cid) };
        match res {
            Ok(_) => {
                info!("found free cid {} for use by guest VM", cid);
                let vsock_config = VsockConfig {
                    guest_fd: fd,
                    guest_cid: cid,
                };
                return Ok(vsock_config);
            }
            Err(err_code) => {
                info!("cid {} is already taken; trying the next one", cid);
                let _ = close(fd);

                // EADDRINUSE means the cid is in-use, we fail on any error
                // other than EADDRINUSE
                if err_code != nix::Error::EADDRINUSE {
                    return Err(map_nix_error(
                        format!("Unable to ioctl vhost-vsock device: {}", VHOST_VSOCK_DEV),
                        err_code,
                    ));
                }
            }
        }

        cid = cid.checked_add(1).ok_or(RunnerError::NoAvailableCidFound)?;
        // Vsock cid is u32. Because of ioctl syscall we need to pass u64.
        // Therefore, we manually check against maximum possible value here.
        if cid > (u32::MAX as u64) {
            return Err(RunnerError::NoAvailableCidFound);
        }
    }
}

fn build_qemu_command(
    run_mode: RunMode,
    vm_run_args: VmRunArgs,
    vsock_config: &VsockConfig,
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
    let mut command = Command::new(QEMU_EXECUTABLE); 

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
            vsock_config.guest_fd.as_raw_fd(), vsock_config.guest_cid
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
    
    debug!("built qemu command {:?}", command);

    command
}

impl Platform for AmdSevVm {
    type RunArgs = VmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let vsock_config = get_available_guest_cid_with_fd()?;
        let child = build_qemu_command(RunMode::AmdSevVm, run_args.into(), &vsock_config)
            .spawn()
            .map_err(|e| (e, "failed to spawn amd sev snp vm through qemu"))?;
        Ok(RunningVm {
            child,
            _vsock_config: vsock_config,
        })
    }
}

impl Platform for VmSimulator {
    type RunArgs = VmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let vsock_config = get_available_guest_cid_with_fd()?;
        let child = build_qemu_command(RunMode::VmSimulator, run_args.into(), &vsock_config)
            .spawn()
            .map_err(|e| (e, "failed to spawn vm through qemu"))?;
        Ok(RunningVm {
            child,
            _vsock_config: vsock_config,
        })
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
