use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{anyhow, Context, Result};
use cargo_toml::Manifest;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the given ELF as an enclave image", long_about = None)]
struct Cli {
    #[command(flatten)]
    common_args: CommonArgs,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args)]
struct CommonArgs {
    #[arg(long)]
    simulate: bool,

    #[arg(long)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    AmdSevSnp(CargoArgs),
    AwsNitro(CargoArgs),
}

struct AmdSevSnpCli {
    common_args: CommonArgs,
    amd_sev_snp_args: CargoArgs,
}

struct AwsNitroCli {
    common_args: CommonArgs,
    aws_nitro_args: CargoArgs,
}

/// Arguments inserted by cargo itself at the end of the invocation
#[derive(Clone, Debug, Args)]
#[command(about = "")]
struct CargoArgs {
    /// Path to the x86_64-unknown-linux-fortanixvme ELF binary
    #[arg(value_parser=parse_elf_path)]
    elf_path: PathBuf,

    #[arg(trailing_var_arg = true)]
    others: Vec<String>,
}

impl CargoArgs {
    pub fn eif_path(&self) -> PathBuf {
        let mut eif_path = self.elf_path.clone();
        eif_path.set_extension("elf");
        eif_path
    }

    pub fn uki_path(&self) -> PathBuf {
        let mut uki_path = self.elf_path.clone();
        uki_path.set_extension("efi");
        uki_path
    }
}

fn parse_elf_path(arg: &str) -> Result<PathBuf> {
    let elf_path = PathBuf::from(arg);
    if !elf_path.is_file() {
        return Err(anyhow!(
            "provided elf path is not an existing filename: {}",
            elf_path.display()
        ));
    } else {
        Ok(elf_path)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct CargoTomlMetadata {
    fortanix_vme: FortanixVmeConfig,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
#[rustfmt::skip] // contains long lines because of links and they may wrapped by mistake
/// This config is mainly intended for args of ftxvme-elf2eif and nitro-cli run-enclave.
/// See their args documentation for more info about these opts:
/// https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-run-enclave.html#cmd-nitro-run-enclave-options
/// https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-build-enclave.html#cmd-nitro-build-enclave-options
struct FortanixVmeConfig {
    // TODO: unused - remove this? Then we don't need to make `FortanixVmeConfig` generic
    /// A custom name given to the enclave. If not specified,
    /// the name of the .eif file is used.
    enclave_name: Option<String>,

    /// Specifies the number of vCPUs to allocate to the enclave.
    cpu_count: Option<u32>,

    /// Specifies the amount of memory (in MiB) to allocate to the enclave.
    /// Should be at least 64 MiB.
    memory: Option<u64>,

    // TODO: unused - remove this? Then we don't need to make `FortanixVmeConfig` generic
    /// This enables debug mode of `nitro-cli run-enclave`, `false` by default.
    debug_mode: bool,
}

impl FortanixVmeConfig {
    /// Tries to parse Cargo.toml for `package.metadata.fortanix-vme` and uses
    /// it if found. If some required values are missing in the the metadata,
    /// default ones are used.
    /// If no metadata is specified, we construct the config only using the
    /// default versions of required values.
    fn get() -> anyhow::Result<FortanixVmeConfig> {
        let manifest_path = Path::new(
            &std::env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?,
        )
        .join("Cargo.toml");

        let fortanix_vme_metadata =
            Manifest::<CargoTomlMetadata>::from_path_with_metadata(&manifest_path)?
                .package
                .map(|package| package.metadata.map(|metadata| metadata.fortanix_vme))
                .flatten()
                .unwrap_or_default();

        Ok(fortanix_vme_metadata)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let fortanix_vme_config = FortanixVmeConfig::get()?;

    match cli.command {
        Commands::AmdSevSnp(amd_sev_snp_args) => {
            let amd_sev_snp_cli = AmdSevSnpCli {
                common_args: cli.common_args,
                amd_sev_snp_args,
            };
            cargo_run_sev_snp_vm(amd_sev_snp_cli, fortanix_vme_config)
        }
        Commands::AwsNitro(aws_nitro_args) => {
            let aws_nitro_cli = AwsNitroCli {
                common_args: cli.common_args,
                aws_nitro_args,
            };
            cargo_run_nitro_enclave(aws_nitro_cli, fortanix_vme_config)
        }
    }
}

fn cargo_run_sev_snp_vm(
    amd_sev_snp_cli: AmdSevSnpCli,
    fortanix_vme_config: FortanixVmeConfig,
) -> Result<(), anyhow::Error> {
    let AmdSevSnpCli {
        common_args,
        amd_sev_snp_args,
    } = amd_sev_snp_cli;

    let uki_path = amd_sev_snp_args.uki_path();

    // TODO: we can assume this is installed right?
    let mut ftxvme_elf2uki = Command::new("ftxvme-elf2uki");
    ftxvme_elf2uki
        .arg("--app")
        .arg(&amd_sev_snp_args.elf_path)
        .arg("--output-path")
        .arg(&uki_path)
        .arg("--cmdline")
        .arg("console=ttyS0 earlyprintk=serial"); //TODO: should we use this as default?
    run_command(ftxvme_elf2uki)?;

    let mut fortanix_vme_runner = Command::new("fortanix-vme-runner");
    fortanix_vme_runner.arg("--enclave-file").arg(&uki_path);

    add_runner_config_args(&mut fortanix_vme_runner, &fortanix_vme_config);

    add_runner_common_args(&mut fortanix_vme_runner, &common_args);

    fortanix_vme_runner.arg("amd-sev-snp");
    add_other_args(&mut fortanix_vme_runner, amd_sev_snp_args.others);

    run_command(fortanix_vme_runner)?;

    Ok(())
}

fn cargo_run_nitro_enclave(
    aws_nitro_cli: AwsNitroCli,
    fortanix_vme_config: FortanixVmeConfig,
) -> Result<()> {
    let AwsNitroCli {
        common_args,
        aws_nitro_args,
    } = aws_nitro_cli;

    let eif_path = aws_nitro_args.eif_path();

    let mut ftxvme_elf2eif = Command::new("ftxvme-elf2eif");
    ftxvme_elf2eif
        .arg("--elf-path")
        .arg(&aws_nitro_args.elf_path)
        .arg("--output-path")
        .arg(&eif_path);
    run_command(ftxvme_elf2eif)?;

    let mut fortanix_vme_runner = Command::new("fortanix-vme-runner");
    fortanix_vme_runner.arg("--enclave-file").arg(&eif_path);

    add_runner_config_args(&mut fortanix_vme_runner, &fortanix_vme_config);

    add_runner_common_args(&mut fortanix_vme_runner, &common_args);

    fortanix_vme_runner.arg("aws-nitro");
    // Use elf path as executable name in the runner
    fortanix_vme_runner
        .arg("--executable_name")
        .arg(&aws_nitro_args.elf_path);
    add_other_args(&mut fortanix_vme_runner, aws_nitro_args.others);

    run_command(fortanix_vme_runner)?;

    Ok(())
}

fn add_runner_common_args(fortanix_vme_runner: &mut Command, common_args: &CommonArgs) {
    if common_args.simulate {
        fortanix_vme_runner.arg("--simulate");
    }

    if common_args.verbose {
        fortanix_vme_runner.arg("--verbose");
    }
}

fn add_runner_config_args(
    fortanix_vme_runner: &mut Command,
    fortanix_vme_config: &FortanixVmeConfig,
) {
    if let Some(cpu_count) = fortanix_vme_config.cpu_count {
        fortanix_vme_runner.args(["--cpu-count", &cpu_count.to_string()]);
    }

    if let Some(memory) = fortanix_vme_config.memory {
        fortanix_vme_runner.args(["--memory", &memory.to_string()]);
    }
}

fn add_other_args<I, S>(fortanix_vme_runner: &mut Command, other_args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut peek = other_args.into_iter().peekable();
    if !peek.peek().is_none() {
        fortanix_vme_runner.arg("--");
        fortanix_vme_runner.args(peek);
    }
}

#[derive(Debug, Error)]
enum CommandFail {
    #[error("Failed to run {0}")]
    Io(String, #[source] std::io::Error),
    #[error("While running {0} got exit status {1}")]
    Status(String, ExitStatus),
}

fn run_command(mut cmd: Command) -> Result<(), CommandFail> {
    match cmd.status() {
        Err(e) => Err(CommandFail::Io(format!("{:?}", cmd), e)),
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(CommandFail::Status(format!("{:?}", cmd), status)),
    }
}
