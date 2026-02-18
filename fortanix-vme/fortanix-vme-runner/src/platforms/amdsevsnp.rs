use log::{debug, info};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::close;
use nix::Error;
use rand::{self, Rng};
use std::borrow::{Borrow, Cow};
use std::os::fd::{AsRawFd, OwnedFd};
use std::{
    path::PathBuf,
    process::{Child, Command},
};

use crate::RunnerError;

use super::Platform;

/// The arguments used by the `run-enclave` command in simulator mode.
#[derive(Debug)]
pub struct SimulatorVmRunArgs {
    pub common_vm_run_args: CommonVmRunArgs,
}

/// The arguments used by the `run-enclave` command in amd-sev mode.
#[derive(Debug)]
pub struct AmdSevVmRunArgs {
    pub common_vm_run_args: CommonVmRunArgs,
    /// The id block that should be passed in upon
    pub id_block_args: Option<IdBlockArgs>,
}

#[derive(Debug, Clone)]
pub struct CommonVmRunArgs {
    /// The path to the VM image file.
    pub uki_path: PathBuf,
    /// The path to the enclave image file.
    pub firmware_image_path: PathBuf,
    /// The amount of memory that will be given to the enclave.
    pub memory_mib: u64,
    /// The number of CPUs that the enclave will receive.
    pub cpu_count: u32,
}

#[derive(Debug)]
pub struct IdBlockArgs {
    /// Base-64 encoded value of the id_block structure
    pub id_block: String,

    /// Base-64 encoded value of the id_auth authentication information structure
    pub id_auth: String,

    /// Whether the author key is used
    pub author_key_enabled: bool,
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

trait UseCaseQemuArgs {
    const PROCESSOR_NAME: &str;

    fn common_vm_run_args(&self) -> Cow<'_, CommonVmRunArgs>;

    fn add_use_case_arguments(&self, command: &mut Command);
}

impl UseCaseQemuArgs for SimulatorVmRunArgs {
    const PROCESSOR_NAME: &str = "host";

    fn common_vm_run_args(&self) -> Cow<'_, CommonVmRunArgs> {
        Cow::Borrowed(&self.common_vm_run_args)
    }

    fn add_use_case_arguments(&self, _command: &mut Command) {}
}

impl UseCaseQemuArgs for AmdSevVmRunArgs {
    const PROCESSOR_NAME: &str = AMD_PROCESSOR;

    fn common_vm_run_args(&self) -> Cow<'_, CommonVmRunArgs> {
        Cow::Borrowed(&self.common_vm_run_args)
    }

    fn add_use_case_arguments(&self, command: &mut Command) {
        command
            .arg("-machine")
            .arg("confidential-guest-support=sev0");
        command.arg("-object");

        let sev_snp_guest_arg =
            "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on";
        if let Some(IdBlockArgs {
            id_block,
            id_auth,
            author_key_enabled,
        }) = &self.id_block_args
        {
            command.arg(format!(
                "{},id-block={},id-auth={},author-key-enabled={},policy={:#x}",
                sev_snp_guest_arg,
                id_block,
                id_auth,
                if *author_key_enabled { "on" } else { "off" },
                DEFAULT_POLICY
            ));
        } else {
            command.arg(sev_snp_guest_arg);
        }
    }
}

// TODO(RTE-789): decide what processor type well use in prod
const AMD_PROCESSOR: &str = "EPYC-v4";
// TODO: proper policy
const DEFAULT_POLICY: u64 = 0x20000;

fn map_nix_error<I: Into<Cow<'static, str>>>(msg: I, err: Error) -> RunnerError {
    RunnerError::Io(Some(msg.into()), err.into())
}

// Define the VHOST_VSOCK_SET_GUEST_CID ioctl
// In C: _IOW(VHOST_VIRTIO, 0x60, __u64)
const VHOST_VIRTIO: u8 = 0xAF;
const VHOST_VSOCK_DEV: &str = "/dev/vhost-vsock";
nix::ioctl_write_ptr!(set_guest_cid, VHOST_VIRTIO, 0x60, u64);

// Port numbers below 1024 are called privileged ports.
const CID_START: u32 = 1024;

// This function basically opens vhost-vsock device and
// tries to allocate a cid number. If allocation succeeds
// we simply re-use it along with the file descriptor.
fn get_available_guest_cid_with_fd() -> Result<VsockConfig, RunnerError> {
    let random_start = rand::thread_rng().gen_range(CID_START, u32::MAX);
    for cid in (random_start..u32::MAX).chain(CID_START..random_start) {
        // set_guest_cid expects u64 due to underlying ioctl call.
        let cid = cid as u64;
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
    }

    Err(RunnerError::NoAvailableCidFound)
}

fn build_qemu_command_common<V: UseCaseQemuArgs>(
    vm_run_args: V,
    vsock_config: &VsockConfig,
) -> Command {
    const QEMU_EXECUTABLE: &str = "qemu-system-x86_64";
    const QEMU_MACHINE: &str = "q35";

    let common_vm_run_args = vm_run_args.common_vm_run_args();
    let CommonVmRunArgs {
        uki_path,
        firmware_image_path,
        memory_mib,
        cpu_count,
    } = common_vm_run_args.borrow();
    let memory_size = format!("{}M", memory_mib);

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
            vsock_config.guest_fd.as_raw_fd(),
            vsock_config.guest_cid
        ));

    // CPU
    command
        .arg("-cpu")
        .arg(<V as UseCaseQemuArgs>::PROCESSOR_NAME);

    // Memory
    command.arg("-machine").arg("memory-backend=ram1");
    command.arg("-object").arg(format!(
        "memory-backend-memfd,id=ram1,share=true,size={}",
        memory_size
    ));

    // Images
    command.arg("-kernel").arg(uki_path);
    command.arg("-bios").arg(firmware_image_path);

    vm_run_args.add_use_case_arguments(&mut command);

    debug!("built qemu command {:?}", command);

    command
}

impl Platform for AmdSevVm {
    type RunArgs = AmdSevVmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let vsock_config = get_available_guest_cid_with_fd()?;
        let child = build_qemu_command_common(run_args.into(), &vsock_config)
            .spawn()
            .map_err(|e| (e, "failed to spawn amd sev snp vm through qemu"))?;
        Ok(RunningVm {
            child,
            _vsock_config: vsock_config,
        })
    }
}

impl Platform for VmSimulator {
    type RunArgs = SimulatorVmRunArgs;

    type EnclaveDescriptor = RunningVm;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, RunnerError> {
        let vsock_config = get_available_guest_cid_with_fd()?;
        let child = build_qemu_command_common(run_args.into(), &vsock_config)
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
