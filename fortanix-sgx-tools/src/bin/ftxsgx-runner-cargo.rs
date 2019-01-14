#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::process::{self, Command, ExitStatus};
use failure::{Error, ResultExt};

const HEAP_SIZE: u64 = 0x2000000;
const SSAFRAMESIZE: u32 = 1;
const STACK_SIZE: u32 = 0x20000;
const DEBUG: bool = true;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Target {
    heap_size: Option<u64>,
    ssaframesize: Option<u32>,
    stack_size: Option<u32>,
    threads: Option<u32>,
    debug: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Metadata {
    fortanix_sgx: Target
}

#[derive(Deserialize, Debug)]
struct Package {
    metadata: Metadata
}

#[derive(Deserialize, Debug)]
struct Config {
    package: Package
}

#[derive(Debug, Fail)]
enum CommandFail {
    #[fail(display = "failed to run {}, {}", _0, _1)]
    Io(String, io::Error),
    #[fail(display = "while running {} got {}", _0, _1)]
    Status(String, ExitStatus),
}

fn run_command(mut cmd: Command) -> Result<(), CommandFail> {
    match cmd.status() {
        Err(e) => Err(CommandFail::Io(format!("{:?}", cmd), e)),
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(CommandFail::Status(format!("{:?}", cmd), status)),
    }
}

fn run() -> Result<(), Error> {
    let key = "CARGO_MANIFEST_DIR";
    let mut filepath = env::var_os(key)
        .ok_or_else(|| format_err!("{} is not defined in the environment.", key))?;
    filepath.push("/Cargo.toml");
    let mut file = File::open(filepath).context("Unable to open the manifest")?;
    let mut content = String::new();
    file.read_to_string(&mut content).context("Unable to read the manifest")?;
    let config: Config = toml::from_str(&content).context("Unable to parse the manifest")?;
    let heap_size = config.package.metadata.fortanix_sgx.heap_size.unwrap_or(HEAP_SIZE).to_string();
    let ssaframesize = config.package.metadata.fortanix_sgx.ssaframesize.unwrap_or(SSAFRAMESIZE).to_string();
    let stack_size = config.package.metadata.fortanix_sgx.stack_size.unwrap_or(STACK_SIZE).to_string();
    let available_cpus = num_cpus::get() as u32;
    let threads = config.package.metadata.fortanix_sgx.threads.unwrap_or(available_cpus).to_string();
    let debug = config.package.metadata.fortanix_sgx.debug.unwrap_or(DEBUG);

    let args: Vec<String> = env::args().collect();
    let mut ftxsgx_elf2sgxs_command = Command::new("ftxsgx-elf2sgxs");
    ftxsgx_elf2sgxs_command.arg(&args[1])
        .arg("--heap-size")
        .arg(heap_size)
        .arg("--ssaframesize")
        .arg(ssaframesize)
        .arg("--stack-size")
        .arg(stack_size)
        .arg("--threads")
        .arg(threads);
    if debug {
        ftxsgx_elf2sgxs_command.arg("--debug");
    }
    run_command(ftxsgx_elf2sgxs_command)?;

    let bin_with_ext = args[1].clone() + ".sgxs";
    let mut sgxs_append_command = Command::new("sgxs-append");
    sgxs_append_command.arg("-i")
        .arg(&bin_with_ext);
    run_command(sgxs_append_command)?;

    let mut ftxsgx_runner_command = Command::new("ftxsgx-runner");
    ftxsgx_runner_command.arg(&bin_with_ext);
    run_command(ftxsgx_runner_command)?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {}", e);
        process::exit(match e.downcast_ref::<CommandFail>() {
            Some(CommandFail::Status(_, status)) => status.code().unwrap(),
            _ => 1,
        })
    }
}
