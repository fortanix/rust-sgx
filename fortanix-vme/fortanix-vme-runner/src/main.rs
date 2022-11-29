use clap::Parser;
use fortanix_vme_runner::{EnclaveRunner, NitroEnclaves};
use nitro_cli::common::commands_parser::RunEnclavesArgs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the eif file
    #[arg(short, long)]
    enclave_file: String,

    /// The number of CPUs that should be allcated to the enclave
    #[arg(short, long)]
    cpu_count: u32,

    /// The amount of memory that should be allcated to the enclave (in MiB)
    #[arg(short, long)]
    memory: usize,
}

impl From<&Cli> for RunEnclavesArgs {
    fn from(cli: &Cli) -> RunEnclavesArgs {
        RunEnclavesArgs {
            eif_path: cli.enclave_file.clone(),
            enclave_cid: None,
            memory_mib: cli.memory as u64,
            cpu_ids: None,
            debug_mode: None,
            cpu_count: Some(cli.cpu_count),
            enclave_name: None,
        }
    }
}

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    EnclaveRunner::<NitroEnclaves>::run(&cli).expect("Runner failed unexpectedly");
}
