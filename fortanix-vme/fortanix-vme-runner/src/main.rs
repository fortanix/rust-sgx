use anyhow::{anyhow, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_verbosity_flag::WarnLevel;
use fortanix_vme_abi::SERVER_PORT;
use fortanix_vme_runner::{
    read_eif_with_metadata, EnclaveRunner, NitroEnclaves, Platform, ReadEifResult, Simulator,
    SimulatorArgs,
};
use log::info;
use nitro_cli::common::commands_parser::RunEnclavesArgs as NitroCliArgs;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
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
    #[arg(
        short,
        long,
        help = "Path to the enclave source file - an EIF image in the case of AWS nitro, and a UKI image otherwise"
    )]
    enclave_file: String,

    #[arg(
        short,
        long,
        help = "The number of CPUs that should be allocated to the enclave. Cannot be provided when the `--simulate` flag is provided."
    )]
    cpu_count: Option<u32>,

    #[arg(
        short,
        long,
        help = "The amount of memory that should be allcated to the enclave (in MiB). Cannot be provided when the `--simulate` flag is provided."
    )]
    memory: Option<usize>,

    #[arg(
        short,
        long,
        help = "Run enclave on simulated version of the target platform"
    )]
    simulate: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Nitro(NitroArgs),
}

struct NitroCli {
    common_args: CommonArgs,
    nitro_args: NitroArgs,
}

#[derive(Args, Debug)]
struct NitroArgs {
    /// `ENCLAVE_FILE` points to an ELF, not an EIF (only available in simulation mode)
    #[arg(long)]
    elf: bool,

    #[arg(last = true)]
    args: Vec<String>,
}

impl NitroCli {
    fn to_nitro_cli_args(&self) -> Result<NitroCliArgs> {
        let cpu_count = self
            .common_args
            .cpu_count
            .ok_or(anyhow!("missing `cpu_count` argument"))?;
        let memory_mib = self
            .common_args
            .memory
            .ok_or(anyhow!("missing `memory` argument"))? as u64;

        Ok(NitroCliArgs {
            eif_path: self.common_args.enclave_file.clone(),
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(cli.verbose.into())
        .init();

    let common_args = cli.common_args;
    match cli.command {
        Commands::Nitro(nitro_args) => {
            if !common_args.simulate && nitro_args.elf {
                Err(Cli::command().error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "elf argument can only be passed in simulate mode",
                ))?
            }
            run_nitro_enclave(NitroCli {
                common_args,
                nitro_args,
            })
        }
    }
}

fn run_nitro_enclave(nitro_cli: NitroCli) -> Result<()> {
    let NitroCli {
        common_args,
        nitro_args,
    } = &nitro_cli;
    if common_args.simulate {
        let elf_path: PathBuf;
        let img_name;

        if nitro_args.elf {
            elf_path = common_args.enclave_file.into();
            img_name = elf_path
                .file_name()
                .unwrap_or_default()
                .display()
                .to_string();
        } else {
            let ReadEifResult { mut eif, metadata } =
                read_eif_with_metadata(&common_args.enclave_file)
                    .context("Failed to read EIF file")?;

            //TODO also extract env/cmd file and make sure the application is executed with this
            //context
            let elf = eif.application().context("Failed to parse enclave file")?;
            elf_path = create_elf(elf).context("Failed to create executable file")?;

            img_name = metadata.img_name;

            info!("Simulating enclave as {}", elf_path.display(),);
        }
        let mut runner: EnclaveRunner<Simulator> = create_runner();
        let args = SimulatorArgs::new(elf_path);
        runner
            .run_enclave(args, img_name, nitro_args.args)
            .context("Failed to run enclave")?;
        runner.wait();
    } else {
        let metadata = read_eif_with_metadata(&common_args.enclave_file)
            .context("Failed to read EIF file")?
            .metadata;
        let mut runner: EnclaveRunner<NitroEnclaves> = create_runner();
        let args = nitro_cli
            .to_nitro_cli_args()

            .context("Failed to parse arguments")?;
        runner
            .run_enclave(args, metadata.img_name, nitro_cli.nitro_args.args)
            .context("Failed to run enclave")?;
        runner.wait();
    };

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

fn create_runner<P: Platform + 'static>() -> EnclaveRunner<P> {
    match EnclaveRunner::new() {
        Ok(runner) => runner,
        Err(e) if e.kind() == IoErrorKind::AddrInUse => {
            panic!("Server failed. Do you already have a runner running on vsock port {}? (Error: {:?})", SERVER_PORT, e);
        }
        Err(e) => panic!("Server failed. Error: {:?}", e),
    }
}
