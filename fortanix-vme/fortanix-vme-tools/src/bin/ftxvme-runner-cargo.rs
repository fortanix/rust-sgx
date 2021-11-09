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

const DEBUG: bool = true;
const RUNNER: &'static str = "ftxvme-runner";

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
struct Target {
    debug: Option<bool>,
    runner: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
struct Metadata {
    #[serde(default)]
    fortanix_vme: Target
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
    println!("run: {:?}", cmd);
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
    let custom_values  = config.package.metadata.fortanix_vme;
    let debug = custom_values.debug.unwrap_or(DEBUG);
    let runner = custom_values.runner.unwrap_or(RUNNER.to_owned());

    let args: Vec<String> = env::args().collect();
    let mut ftxvme_elf2eif_command = Command::new("ftxvme-elf2eif");
    ftxvme_elf2eif_command.arg(&args[1]);
    run_command(ftxvme_elf2eif_command)?;

    let mut ftxvme_runner_command = Command::new(runner);
    ftxvme_runner_command.arg(args[1].clone() + ".eif");
    if args.len() > 2 {
        ftxvme_runner_command.arg("--");
        ftxvme_runner_command.args(&args[2..]);
    }

    run_command(ftxvme_runner_command)?;

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
