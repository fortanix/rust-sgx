use anyhow::{anyhow, Context, Result};
use b64_ct::{ToBase64, STANDARD};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_verbosity_flag::WarnLevel;
use confidential_vm_blobs::{AMD_SEV_OVMF_PATH, VANILLA_OVMF_PATH};
use enclave_runner::EnclaveBuilder;
use fortanix_vme_runner::{
    read_eif_with_metadata, AmdSevVm, AmdSevVmRunArgs, CommonVmRunArgs,
    EnclaveBuilder as EnclaveBuilderVme, EnclaveSimulator, EnclaveSimulatorArgs, IdBlockArgs,
    NitroEnclaves, Platform, ReadEifResult, SimulatorVmRunArgs, VmSimulator,
};
use log::info;
use nitro_cli::common::commands_parser::RunEnclavesArgs as NitroRunArgs;
use sev::measurement::idblock_types::{IdAuth, IdBlock};
use sev::parser::ByteParser;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{Error as IoError, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

type DefaultLogLevel = WarnLevel;

#[derive(Parser, Debug)]
#[command(author, version, about = "Run the given enclave image file", long_about = None)]
struct Cli {
    #[command(flatten)]
    common_args: CommonArgs,

    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<DefaultLogLevel>,
}

const DEFAULT_CPU_COUNT: u32 = 1;
const DEFAULT_MEMORY_SIZE_MIB: u64 = 512;

#[derive(Args, Debug)]
struct CommonArgs {
    /// Path to the enclave source file - an EIF image in the case of AWS nitro, and a UKI image otherwise
    #[arg(short, long)]
    enclave_file: PathBuf,

    // TODO(RTE-745): the `cpu_count` is not currently being used for AMD-SEV
    /// The number of (v)CPUs that should be allocated to the enclave
    #[arg(short, long, default_value_t = DEFAULT_CPU_COUNT, global=true)]
    cpu_count: u32,

    ///The amount of memory that should be allocated to the enclave (in MiB)
    #[arg(short, long, default_value_t = DEFAULT_MEMORY_SIZE_MIB, global=true)]
    memory: u64,

    ///Run enclave on simulated version of the target platform
    #[arg(short, long, global = true)]
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

    /// Name for the VM, passed as argv[0] by the runner
    #[arg(long, default_value = "FortanixAmdSevSnpVm")]
    executable_name: String,

    #[command(flatten)]
    id_block_args: Option<IdBlockCliArgs>,

    /// Arguments to pass to VM's `fn main` (excluding argv[0])
    #[arg(last = true)]
    vm_args: Vec<String>,
}

#[derive(Clone, Debug, Args)]
#[group(requires_all(["id_block_file", "id_auth_file"]))]
struct IdBlockCliArgs {
    /// Path to file containing the `id_block` structure
    #[arg(long = "id-block", required = false)]
    id_block_file: PathBuf,

    /// Path to file containing `id_auth` authentication information structure
    #[arg(long = "id-auth", required = false)]
    id_auth_file: PathBuf,
}

#[derive(Clone, Debug, Args)]
struct AwsNitroArgs {
    /// `ENCLAVE_FILE` points to an ELF, not an EIF (only available in simulation mode)
    #[arg(long)]
    elf: bool,

    /// Arguments to pass to enclave's `fn main` (excluding argv[0])
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
    fn to_common_vm_run_args(&self) -> Result<CommonVmRunArgs> {
        let firmware_image_path = self.amd_sev_snp_args.firmware_image_path.as_ref();

        let firmware_image_path = match firmware_image_path {
            Some(path) => path,
            None => Path::new(if self.common_args.simulate {
                check_file_open(VANILLA_OVMF_PATH)?;
                VANILLA_OVMF_PATH
            } else if self.amd_sev_snp_args.id_block_args.is_some() {
                Err(Cli::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "must explicitly specify firmware image path when using signed enclaves",
                ))?
            } else {
                check_file_open(AMD_SEV_OVMF_PATH)?;
                AMD_SEV_OVMF_PATH
            }),
        }
        .to_owned();
        let cpu_count = self.common_args.cpu_count;
        let memory_mib = self.common_args.memory;

        Ok(CommonVmRunArgs {
            uki_path: self.common_args.enclave_file.clone(),
            firmware_image_path,
            memory_mib,
            cpu_count,
        })
    }
}

pub fn check_file_open<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let _ =
        File::open(path).with_context(|| format!("cannot open file at path {}", path.display()));
    Ok(())
}

impl TryFrom<IdBlockCliArgs> for IdBlockArgs {
    type Error = anyhow::Error;

    fn try_from(value: IdBlockCliArgs) -> Result<Self> {
        let id_block_data =
            std::fs::read(value.id_block_file).context("failed to read id block from file")?;
        let id_auth_data =
            std::fs::read(value.id_auth_file).context("failed to read id auth from file")?;

        // Parse both provided structs to sanity-check input
        let _id_block_parsed = IdBlock::from_bytes(&id_block_data)
            .context("provided `id_block` does not represent an id block structure")?;
        let id_auth_parsed = IdAuth::from_bytes(&id_auth_data)
            .context("provided `id_auth` does not represent an id auth structure")?;

        // We check whether or not `IdAuth::author_pub_key` is zeroes as a proxy
        // for whether `AUTHOR_KEY_EN` needs to be set
        let author_pub_key = id_auth_parsed.author_pub_key;
        // Workaround because `SevEcdsaPubKey` does not implement PartialEq
        let author_key_enabled = author_pub_key.to_bytes()?.iter().all(|byte| byte == &0);
        info!(
            "automatically detected that an author key is {}",
            if author_key_enabled {
                "used"
            } else {
                "not used"
            }
        );

        Ok(Self {
            id_block: id_block_data.to_base64(STANDARD),
            id_auth: id_auth_data.to_base64(STANDARD),
            author_key_enabled,
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
        Commands::AmdSevSnp(amd_sev_snp_args) => {
            if common_args.simulate && amd_sev_snp_args.id_block_args.is_some() {
                Err(Cli::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    "cannot pass in id block arguments in simulation mode",
                ))?
            }
            run_amd_sev_enclave(AmdSevSnpCli {
                common_args,
                amd_sev_snp_args,
            })
        }
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
    let common_vm_run_args = amd_sev_cli.to_common_vm_run_args()?;
    let AmdSevSnpCli {
        common_args,
        amd_sev_snp_args,
    } = amd_sev_cli;

    if common_args.simulate {
        info!("running in simulation mode without confidential computing protection");
        run_to_completion::<VmSimulator>(
            SimulatorVmRunArgs { common_vm_run_args },
            amd_sev_snp_args.executable_name,
            amd_sev_snp_args.vm_args,
        )
    } else {
        let run_args = AmdSevVmRunArgs {
            common_vm_run_args,
            id_block_args: amd_sev_snp_args
                .id_block_args
                .map(|args| args.try_into())
                .transpose()?,
        };
        run_to_completion::<AmdSevVm>(
            run_args,
            amd_sev_snp_args.executable_name,
            amd_sev_snp_args.vm_args,
        )
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
                    .context("failed to read EIF file")?;

            //TODO also extract env/cmd file and make sure the application is executed with this
            //context
            let elf = eif.application().context("failed to parse enclave file")?;
            elf_path = create_elf(elf).context("failed to create executable file")?;

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
            .context("failed to read EIF file")?
            .metadata;
        let run_args = nitro_cli
            .to_nitro_cli_run_args()
            .context("failed to parse arguments")?;

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
) -> Result<(), anyhow::Error>
where
    <P as Platform>::RunArgs: Send + Sync,
{
    let enclave_runner = EnclaveBuilderVme::<P, _>::new(run_args, enclave_name)?;
    let mut enclave_runner = EnclaveBuilder::new(enclave_runner);
    enclave_runner.args(enclave_args);
    let enclave = enclave_runner
        .build(())
        .context("failed to build enclave runner")?;
    enclave.run().context("failed to run enclave")?;
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
