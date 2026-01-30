use anyhow::{anyhow, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_verbosity_flag::WarnLevel;
use confidential_vm_blobs::maybe_vendored::MaybeVendoredImage;
use confidential_vm_blobs::{AMD_SEV_OVMF, VANILLA_OVMF};
use fortanix_vme_abi::SERVER_PORT;
use fortanix_vme_runner::{
    read_eif_with_metadata, AmdSevVm, EnclaveRunner, EnclaveSimulator, EnclaveSimulatorArgs,
    NitroEnclaves, Platform, ReadEifResult, VmRunArgs, VmSimulator,
};
use log::info;
use nitro_cli::common::commands_parser::RunEnclavesArgs as NitroRunArgs;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Run the given enclave image file", long_about = None)]
struct Cli {
    #[command(flatten)]
    common_args: CommonArgs,

    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<WarnLevel>,
}

#[derive(Args, Debug)]
struct CommonArgs {
    /// Path to the enclave source file - an EIF image in the case of AWS nitro, and a UKI image otherwise
    #[arg(short, long)]
    enclave_file: PathBuf,

    // TODO(RTE-745): the `cpu_count` is not currently being used for AMD-SEV
    /// The number of (v)CPUs that should be allocated to the enclave (2 by default)
    #[arg(short, long, default_value_t = 2)]
    cpu_count: u32,

    ///The amount of memory that should be allcated to the enclave (in MiB)
    #[arg(short, long, default_value_t = 512)]
    memory: u64,

    ///Run enclave on simulated version of the target platform
    #[arg(short, long)]
    simulate: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    AmdSevSnp(AmdSevSnpArgs),
    AwsNitro(AwsNitroArgs),
}

struct AmdSevSnpCli {
    common_args: CommonArgs,
    amd_sev_snp_args: AmdSevSnpArgs,
}

struct AwsNitroCli {
    common_args: CommonArgs,
    aws_nitro_args: AwsNitroArgs,
}

#[derive(Clone, Debug, Args)]
struct AmdSevSnpArgs {
    /// Path to the firmware image file, defaulting to the relevant vendored image if not provided
    #[arg(long = "firmware-image")]
    firmware_image_path: Option<PathBuf>,

    /// Name for the VM in the runner
    #[arg(long, default_value = "FortanixAmdSevSnpVm")]
    vm_name: String,

    #[arg(last = true)]
    vm_args: Vec<String>,
}

#[derive(Clone, Debug, Args)]
struct AwsNitroArgs {
    /// `ENCLAVE_FILE` points to an ELF, not an EIF (only available in simulation mode)
    #[arg(long)]
    elf: bool,

    #[arg(last = true)]
    enclave_args: Vec<String>,
}

impl AwsNitroCli {
    fn to_nitro_cli_run_args(&self) -> Result<NitroRunArgs> {
        let cpu_count = self.common_args.cpu_count;
        let memory_mib = self.common_args.memory;
        let eif_path = self
            .common_args
            .enclave_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_| anyhow!("non-string EIF path provided"))?;

        Ok(NitroRunArgs {
            eif_path,
            enclave_cid: None,
            memory_mib,
            cpu_ids: None,
            debug_mode: false,
            cpu_count: Some(cpu_count),
            enclave_name: None,
            attach_console: true,
        })
    }
}

impl AmdSevSnpCli {
    fn to_vm_run_args(&self, firmware_image_path: PathBuf) -> Result<VmRunArgs> {
        let cpu_count = self.common_args.cpu_count;
        let memory_mib = self.common_args.memory;

        Ok(VmRunArgs {
            uki_path: self.common_args.enclave_file.clone(),
            firmware_image_path,
            memory_mib,
            cpu_count,
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.into())
        .init();

    let common_args = cli.common_args;
    match cli.command {
        Commands::AmdSevSnp(amd_sev_snp_args) => run_amd_sev_enclave(AmdSevSnpCli {
            common_args,
            amd_sev_snp_args,
        }),
        Commands::AwsNitro(aws_nitro_args) => {
            if !common_args.simulate && aws_nitro_args.elf {
                Err(Cli::command().error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "elf argument can only be passed in simulate mode",
                ))?
            }
            run_nitro_enclave(AwsNitroCli {
                common_args,
                aws_nitro_args,
            })
        }
    }
}

fn run_amd_sev_enclave(amd_sev_cli: AmdSevSnpCli) -> Result<()> {
    // NOTE: it's important to not drop this while the VM runs, as it will remove the
    // temporary file that stores the firmware image
    let firmware_image = match amd_sev_cli.amd_sev_snp_args.firmware_image_path.clone() {
        Some(path) => MaybeVendoredImage::from(path),
        None => MaybeVendoredImage::from_vendored(if amd_sev_cli.common_args.simulate {
            VANILLA_OVMF
        } else {
            AMD_SEV_OVMF
        })?,
    };
    let run_args = amd_sev_cli.to_vm_run_args(firmware_image.path().to_owned())?;

    let AmdSevSnpCli {
        common_args,
        amd_sev_snp_args,
    } = amd_sev_cli;
    if common_args.simulate {
        info!("running in simulation mode without confidential computing protection");
        run_to_completion::<VmSimulator>(
            run_args,
            amd_sev_snp_args.vm_name,
            amd_sev_snp_args.vm_args,
        )
    } else {
        run_to_completion::<AmdSevVm>(run_args, amd_sev_snp_args.vm_name, amd_sev_snp_args.vm_args)
    }
}

fn run_nitro_enclave(nitro_cli: AwsNitroCli) -> Result<()> {
    if nitro_cli.common_args.simulate {
        let elf_path: PathBuf;
        let img_name;

        if nitro_cli.aws_nitro_args.elf {
            elf_path = nitro_cli.common_args.enclave_file;
            img_name = elf_path
                .file_name()
                .unwrap_or_default()
                .display()
                .to_string();
        } else {
            let ReadEifResult { mut eif, metadata } =
                read_eif_with_metadata(&nitro_cli.common_args.enclave_file)
                    .context("Failed to read EIF file")?;

            //TODO also extract env/cmd file and make sure the application is executed with this
            //context
            let elf = eif.application().context("Failed to parse enclave file")?;
            elf_path = create_elf(elf).context("Failed to create executable file")?;

            img_name = metadata.img_name;

            info!("simulating enclave as {}", elf_path.display(),);
        }

        let run_args = EnclaveSimulatorArgs::new(elf_path);
        run_to_completion::<EnclaveSimulator>(
            run_args,
            img_name,
            nitro_cli.aws_nitro_args.enclave_args,
        )
    } else {
        let metadata = read_eif_with_metadata(&nitro_cli.common_args.enclave_file)
            .context("Failed to read EIF file")?
            .metadata;
        let run_args = nitro_cli
            .to_nitro_cli_run_args()
            .context("Failed to parse arguments")?;

        run_to_completion::<NitroEnclaves>(
            run_args,
            metadata.img_name,
            nitro_cli.aws_nitro_args.enclave_args,
        )
    }
}

fn run_to_completion<P: Platform + 'static>(
    run_args: P::RunArgs,
    enclave_name: String,
    enclave_args: Vec<String>,
) -> Result<(), anyhow::Error> {
    let mut runner = create_runner::<P>()?;
    runner
        .run_enclave(run_args, enclave_name, enclave_args)
        .context("failed to run enclave")?;
    runner.wait();
    Ok(())
}

fn create_elf(elf: Vec<u8>) -> Result<PathBuf, IoError> {
    fn create_exec() -> Result<(File, PathBuf), IoError> {
        // Unfortunately `tempfile` can't create temporary executable files. We jump through hoops to
        // achieve the same
        let path = format!("/tmp/elf-{:x}", rand::random::<u64>());
        let path = PathBuf::from(path);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .open(path.clone())?;
        Ok((file, path))
    }
    let (mut f, path) = (0..5)
        .map(|_| create_exec())
        .filter(|r| r.is_ok())
        .next()
        .unwrap_or_else(|| create_exec())?;
    f.write(&elf)?;
    f.sync_all()?;
    Ok(path)
}

fn create_runner<P: Platform + 'static>() -> Result<EnclaveRunner<P>> {
    EnclaveRunner::new().map_err(|e| {
        let error_kind = e.kind();
        let wrapped_error = anyhow::Error::new(e);
        if error_kind == IoErrorKind::AddrInUse {
            wrapped_error.context(format!(
                "server failed. Do you already have a runner running on vsock port {}?",
                SERVER_PORT,
            ))
        } else {
            wrapped_error.context("server failed")
        }
    })
}
