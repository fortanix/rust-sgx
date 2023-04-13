use std::{io, path::{Path, PathBuf}, process::{ExitStatus, Command}};

use anyhow::Context;
use clap::Parser;
use cargo_toml::Manifest;
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Convenience macro to make command constructing containing
/// optional args and flags readable.
///
/// ```ignore
/// command! {
///     "command_name" => args(
///         "--opt1"  => ?is_some(value), // Where `value` is an Option<>.
///                                       // `--opt1` is only passed if `value`
///                                       // is Some()
///
///         "--opt2"  => ?is_true(flag),  // Where `flag` is an bool.
///                                       // `--opt2` is only passed if
///                                       // `flag` is true.
///
///         "--opt3"  => val,             // Where `val` is straight away
///                                       // passed to command.arg()
///
///         "--opt4", "--opt5"            // args without values.
///     )
/// }
/// ```
macro_rules! command {
    {
        $name:expr $( => args(
            $( $arg:expr
                $( => ? is_true($flag:expr) )?
                $( => ? is_some($optional:expr) )?
                $( => $val:expr )?
            ),+
        ) )?
    } => {{
        let command = std::process::Command::new($name);

        $(
            let mut command = command;
            $(
                #[allow(unreachable_patterns)]
                match () {
                    // case if arg is determined by a flag
                    $(
                    () if $flag => {command.arg($arg);}
                    () => {},
                    )?

                    // case if arg is determined by an optional val
                    $(
                    () if $optional.is_some() => {command.arg($arg).arg($optional.unwrap());}
                    () => {},
                    )?

                    // case if value can be given to arg straight away
                    $(
                    () => {command.arg($arg).arg($val);}
                    )?

                    // simple arg
                    () => {command.arg($arg);},
                };
            )+
        )?

        command
    }};
}

#[derive(Debug, Error)]
enum CommandFail {
    #[error("Failed to run {0}: {1}")]
    Io(String, io::Error),
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

#[derive(Parser, Debug)]
#[command(about = "Run an x86_64-unknown-linux-fortanixvme EIF binary on an AWS Nitro instance, or on a simulator")]
#[command(author, version, long_about = None)]
struct Cli {
    #[arg(short, long)]
    simulate: bool,

    #[arg(short, long)]
    verbose: bool,

    /// Path of the x86_64-unknown-linux-fortanixvme ELF binary
    #[arg(value_parser = Cli::parse_elf_path)]
    elf_path: PathBuf,
}

impl Cli {
    pub fn parse_elf_path(elf: &str) -> Result<PathBuf, String> {
        let elf = PathBuf::from(elf);
        if elf.file_name().is_none() {
            Err(format!("Provided elf path is not a filename: {}", elf.display()))
        } else {
            Ok(elf)
        }
    }

    pub fn eif_path(&self) -> PathBuf {
        let mut eif_path = self.elf_path
            .clone();
        eif_path.set_extension("elf");
        eif_path
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct CargoTomlMetadata {
    fortanix_vme: FortanixVmeConfig,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
#[rustfmt::skip] // contains long lines because of links and they may wrapped by mistake
/// This config is mainly intended for args of ftxvme-elf2eif and nitro-cli run-enclave.
/// See their args documentation for more info about these opts:
/// https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-run-enclave.html#cmd-nitro-run-enclave-options
/// https://docs.aws.amazon.com/enclaves/latest/user/cmd-nitro-build-enclave.html#cmd-nitro-build-enclave-options
struct FortanixVmeConfig {
    /// A custom name given to the enclave. If not specified,
    /// the name of the .eif file is used.
    enclave_name: Option<String>,

    /// Specifies the number of vCPUs to allocate to the enclave.
    cpu_count: isize,

    /// Specifies the amount of memory (in MiB) to allocate to the enclave.
    /// Should be at least 64 MiB.
    memory: isize,

    /// `false` by default. This enables debug mode of `nitro-cli run-enclave`.
    debug_mode: bool,
}

impl FortanixVmeConfig {
    const DEFAULT_CPU_COUNT: isize = 2;
    const DEFAULT_MEMORY: isize = 512;

    /// Tries to parse Cargo.toml for `package.metadata.fortanix-vme` and uses
    /// it if found. If some required values are missing in the the metadata,
    /// default ones are used.
    /// If no metadata is specified, we construct the config only using the
    /// default versions of required values.
    fn get() -> anyhow::Result<FortanixVmeConfig> {
        let manifest_path = Path::new(&std::env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?)
            .join("Cargo.toml");

        let fortanix_vme_metadata = Manifest::<CargoTomlMetadata>::from_path_with_metadata(&manifest_path)?
            .package
            .map(|package| {
                package.metadata
                    .map(|metadata| metadata.fortanix_vme)
            })
            .flatten()
            .unwrap_or_default();

        Ok(fortanix_vme_metadata)
    }
}

impl Default for FortanixVmeConfig {
    fn default() -> Self {
        Self {
            cpu_count: FortanixVmeConfig::DEFAULT_CPU_COUNT,
            memory: FortanixVmeConfig::DEFAULT_MEMORY,
            debug_mode: false,
            enclave_name: None,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let fortanix_vme_config = FortanixVmeConfig::get()?;

    let ftxvme_elf2eif = command! {
        "ftxvme-elf2eif"   => args(
        "--elf-path"       => cli.elf_path.clone(),
        "--output-path"    => cli.eif_path()
        )
    };

    run_command(ftxvme_elf2eif)?;

    let mut ftxvme_runner = command! {
        "ftxvme-runner" => args(
            "--enclave-file"  => cli.eif_path(),
            "--cpu-count"     => fortanix_vme_config.cpu_count.to_string(),
            "--memory"        => fortanix_vme_config.memory.to_string()
        )
    };

    if cli.simulate {
        ftxvme_runner.arg("--simulate");
    }

    if cli.verbose {
        ftxvme_runner.arg("--verbose");
    }

    ftxvme_runner.spawn().context("Failed to start fortanix-vme-runner")?;

    Ok(())
}
