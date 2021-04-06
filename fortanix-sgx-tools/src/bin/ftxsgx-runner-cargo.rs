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
const UNMAPPED_MEMORY_SIZE: u64 = 0x20000000; // 512 MiB
const SSAFRAMESIZE: u32 = 1;
const STACK_SIZE: u32 = 0x20000;
const DEBUG: bool = true;
const RUNNER: &'static str = "ftxsgx-runner";

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
struct Target {
    heap_size: Option<u64>,
    unmapped_memory_size: Option<u64>,
    ssaframesize: Option<u32>,
    stack_size: Option<u32>,
    threads: Option<u32>,
    debug: Option<bool>,
    runner: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
struct Metadata {
    #[serde(default)]
    fortanix_sgx: Target
}

#[derive(Deserialize, Debug)]
struct Package {
    #[serde(default)]
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
    let custom_values  = config.package.metadata.fortanix_sgx;
    let heap_size = custom_values.heap_size.unwrap_or(HEAP_SIZE).to_string();
    let unmapped_memory_size = custom_values.unmapped_memory_size.unwrap_or(UNMAPPED_MEMORY_SIZE).to_string();
    let ssaframesize = custom_values.ssaframesize.unwrap_or(SSAFRAMESIZE).to_string();
    let stack_size = custom_values.stack_size.unwrap_or(STACK_SIZE).to_string();
    let available_cpus = num_cpus::get() as u32;
    let threads = custom_values.threads.unwrap_or(available_cpus).to_string();
    let debug = custom_values.debug.unwrap_or(DEBUG);
    let runner = custom_values.runner.unwrap_or(RUNNER.to_owned());

    let args: Vec<String> = env::args().collect();
    let mut ftxsgx_elf2sgxs_command = Command::new("ftxsgx-elf2sgxs");
    ftxsgx_elf2sgxs_command.arg(&args[1])
        .arg("--heap-size")
        .arg(heap_size)
        .arg("--unmapped-memory-size")
        .arg(unmapped_memory_size)
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

    let mut ftxsgx_runner_command = Command::new(runner);
    ftxsgx_runner_command.arg(args[1].clone() + ".sgxs");
    if args.len() > 2 {
        ftxsgx_runner_command.arg("--");
        ftxsgx_runner_command.args(&args[2..]);
    }

    run_command(ftxsgx_runner_command)?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {}", e);
        process::exit(match e.downcast_ref::<CommandFail>() {
            Some(CommandFail::Status(_, status)) => status.code().unwrap_or(1),
            _ => 1,
        })
    }
}
