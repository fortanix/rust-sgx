use std::{io, path::{Path, PathBuf}, process::{ExitStatus, Command}};

use anyhow::Context;
use serde::{Serialize, Deserialize};
use cargo_toml::Manifest;
use thiserror::Error;
use once_cell::sync::Lazy;

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

static ARGS: Lazy<Vec<String>> = Lazy::new(|| {
    std::env::args().collect::<Vec<_>>()
});

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
    /// Enables verbose mode of ftxvme-elf2eif.
    verbose: bool,

    /// Path to output eif file
    eif_file_path: PathBuf,

    /// Path to resources, default is `/usr/share/nitro_enclaves/blobs/`.
    /// See blobs in: https://github.com/aws/aws-nitro-enclaves-cli#source-code-components
    resource_path: Option<PathBuf>,

    /// Path to signing certificate. If this is specified,
    /// `private-key` needs to be specified too.
    signing_certificate: Option<PathBuf>,

    /// Path to private key. If this is specified,
    /// `signing-certificate` needs to be specified too.
    private_key: Option<PathBuf>,

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

    fn default_eif_path() -> PathBuf {
        format!("{}.eif", ARGS[1]).into()
    }

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
            verbose: false,
            eif_file_path: FortanixVmeConfig::default_eif_path(),
            resource_path: None,
            signing_certificate: None,
            private_key: None,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let fortanix_vme_config = FortanixVmeConfig::get()?;

    let ftxvme_elf2eif = command! {
        "ftxvme-elf2eif" => args(
            "--input-file"     => &ARGS[1],
            "--output-file"    => &fortanix_vme_config.eif_file_path,
            "--verbose"        => ?is_true(fortanix_vme_config.verbose),
            "--resource-path"  => ?is_some(fortanix_vme_config.resource_path)
        )
    };

    run_command(ftxvme_elf2eif)?;

    // We just try to start fortanix-vme-runner and don't wait on it. So,
    // we don't know if it errors out.
    //
    // fortanix-vme-runner starts a vsock proxy server and
    // is needed if your edp application makes any call to
    // functions like `TcpStream::connect()`.
    // If your application calls `TcpStream::connect("<url:port>")`,
    // this proxy server acts as a bridge for request and responses.
    let mut fortanix_vme_runner = command!("fortanix-vme-runner");
    let mut fortanix_vme_runner = fortanix_vme_runner.spawn().context("Failed to start fortanix-vme-runner")?;

    let nitro_cli_run_enclave = command! {
        "nitro-cli" => args(
            "run-enclave",
            "--enclave-name" => ?is_some(fortanix_vme_config.enclave_name),
            "--cpu-count"    => fortanix_vme_config.cpu_count.to_string(),
            "--eif-path"     => &fortanix_vme_config.eif_file_path,
            "--memory"       => fortanix_vme_config.memory.to_string(),
            "--debug-mode"   => ?is_true(fortanix_vme_config.debug_mode)
        )
    };

    run_command(nitro_cli_run_enclave)?;
    fortanix_vme_runner.wait()?;
    Ok(())
}
