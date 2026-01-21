use clap::Parser;
use fortanix_vme_eif::{eif_types::EifIdentityInfo, FtxEif};
use fortanix_vme_abi::SERVER_PORT;
use fortanix_vme_runner::{EnclaveRunner, NitroEnclaves, Platform, Simulator, SimulatorArgs};
use nitro_cli::common::commands_parser::{RunEnclavesArgs as NitroArgs};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufReader, Error as IoError, ErrorKind as IoErrorKind, Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the eif file
    #[arg(short, long)]
    enclave_file: String,

    /// The number of CPUs that should be allcated to the enclave. Cannot be provided when the
    /// `--simulate` flag is provided.
    #[arg(short, long)]
    cpu_count: Option<u32>,

    /// The amount of memory that should be allcated to the enclave (in MiB). Cannot be provided
    /// when the `--simulate` flag is provided.
    #[arg(short, long)]
    memory: Option<usize>,

    /// Simulate the AWS Nitro Enclave platform
    #[arg(short, long)]
    simulate: bool,

    /// `ENCLAVE_FILE` points to an ELF, not an EIF (only available in simulation mode)
    #[arg(long, requires("simulate"))]
    elf: bool,

    #[arg(short, long)]
    verbose: bool,

    #[arg(last = true)]
    args: Vec<String>,
}

impl TryFrom<&Cli> for NitroArgs {
    type Error = String;

    fn try_from(cli: &Cli) -> Result<NitroArgs, String> {
        let cpu_count = cli.cpu_count.ok_or(String::from("Missing `cpu_count` argument"))?;
        let memory_mib = cli.memory.ok_or(String::from("Missing `memory` argument"))? as u64;

        Ok(NitroArgs {
            eif_path: cli.enclave_file.clone(),
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

impl TryFrom<&Cli> for SimulatorArgs {
    type Error = String;

    fn try_from(cli: &Cli) -> Result<SimulatorArgs, String> {
        if cli.cpu_count.is_none() {
            return Err(String::from("Missing `cpu_count` argument"));
        }
        if cli.memory.is_some() {
            return Err(String::from("Missing `memory` argument"))?;
        }
        Ok(SimulatorArgs::new(PathBuf::from(cli.enclave_file.to_owned())))
    }
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

fn log(cli: &Cli, text: &str) {
    if cli.verbose {
        println!("{}", text);
    }
}

fn create_runner<P: Platform + 'static>() -> EnclaveRunner<P> {
    match EnclaveRunner::new() {
        Ok(runner)                                     => runner,
        Err(e) if e.kind() == IoErrorKind::AddrInUse   => {
            panic!("Server failed. Do you already have a runner running on vsock port {}? (Error: {:?})", SERVER_PORT, e);
        },
        Err(e)                                         => panic!("Server failed. Error: {:?}", e),
    }
}

fn main() {
    struct ReadEifResult<T> {
        eif: FtxEif<T>,
        metadata: EifIdentityInfo,
    }
    fn read_eif(enclave_file: &str) -> ReadEifResult<impl Read + Seek> {
        let f = File::open(enclave_file).expect("Failed to open enclave file");
        let mut eif = FtxEif::new(BufReader::new(f));
        let metadata = eif.metadata().expect("Failed to parse metadata");
        ReadEifResult { eif, metadata }
    }

    let cli = Cli::parse();

    if cli.simulate {
        env_logger::init();

        let elf_path: PathBuf;
        let img_name;

        if cli.elf {
            elf_path = cli.enclave_file.into();
            img_name = elf_path.file_name().unwrap_or_default().display().to_string();
        } else {
            let ReadEifResult { mut eif, metadata } = read_eif(&cli.enclave_file);
            //TODO also extract env/cmd file and make sure the application is executed with this
            //context
            let elf = eif.application()
                .expect("Failed to parse enclave file");
            elf_path = create_elf(elf)
                .expect("Failed to create executable file");

            img_name = metadata.img_name;

            log(&cli, &format!("Simulating enclave as {}", elf_path.display()));
        }

        let mut runner: EnclaveRunner<Simulator> = create_runner();
        let args = SimulatorArgs::new(elf_path);
        runner.run_enclave(args, img_name, cli.args).expect("Failed to run enclave");
        runner.wait();
    } else {
        let mut runner: EnclaveRunner<NitroEnclaves> = create_runner();
        let args: NitroArgs = TryFrom::try_from(&cli).expect("Failed to parse arguments");
        runner.run_enclave(args, read_eif(&cli.enclave_file).metadata.img_name, cli.args).expect("Failed to run enclave");
        runner.wait();
    };
}
