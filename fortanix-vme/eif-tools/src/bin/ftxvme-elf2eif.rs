use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use clap::{Arg, crate_authors, crate_version};
use env_logger;
use log::{debug, info, LevelFilter};
use nitro_cli::build_from_docker;
use tempdir::TempDir;

use eif_tools::*;

/// Create a temporary directory used for creating a docker image.
fn setup_docker_dir(elf_path: &str) -> Result<TempDir> {
    const DOCKERFILE: &str = "
        FROM scratch
        COPY enclave .
        CMD [\"./enclave\"]
    ";
    info!("Setting up docker directory");
    let docker_dir = TempDir::new("elf2eif_docker_dir")?;
    std::fs::copy(elf_path, docker_dir.path().join("enclave").into_os_string())?;
    let mut dockerfile = File::create(docker_dir.path().join("Dockerfile"))?;
    writeln!(dockerfile, "{}", DOCKERFILE)?;
    Ok(docker_dir)
}

fn main() {
    let args = clap::App::new("ftxvme-elf2eif")
        .author(crate_authors!())
        .about("ELF to EIF conversion tool")
        .version(crate_version!())
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Print extra information about the conversion process"))
        .arg(Arg::with_name("elffile")
            .short("i")
            .long("input-file")
            .required(true)
            .value_name("FILE")
            .validator_os(readable_elf_file)
            .help("Path to input ELF file"))
        .arg(Arg::with_name("eiffile")
            .short("o")
            .long("output-file")
            .required(true)
            .value_name("FILE")
            .help("Path to output EIF file"))
        .arg(Arg::with_name("resource-path")
             .short("r")
             .long("resource-path")
             .required(false)
             .value_name("resource_path")
             .help("Path to the resource directory")
             .validator_os(is_directory))
        .arg(Arg::with_name("signing-certificate")
            .short("c")
            .long("signing-certificate")
            .value_name("FILE")
            .validator_os(readable_file)
            .help("Path to signing certificate for signed enclaves"))
        .arg(Arg::with_name("private-key")
            .short("k")
            .long("private-key")
            .value_name("FILE")
            .validator_os(readable_file)
            .help("Path to private key for signed enclaves"))
        .get_matches();

    let verbose = args.is_present("verbose");
    let input_path = args.value_of("elffile").unwrap();
    let output_path = args.value_of("eiffile").unwrap();
    let signing_certificate = args.value_of("signing-certificate").map(|c| c.to_string());
    let private_key = args.value_of("private-key").map(|k| k.to_string());
    let resource_path = args.value_of("resource-path").unwrap_or("/usr/share/nitro_enclaves/blobs/");
    let resource_path = Path::new(resource_path).to_path_buf();
    let mut logger = env_logger::Builder::from_default_env();
    let logger = logger.format(|buf, record| writeln!(buf, "{}", record.args()));
    if verbose {
        logger.filter_level(LevelFilter::Info).init();
    } else {
        logger.filter_level(LevelFilter::Error).init();
    }

    println!("Converting elf file `{}` to eif, please wait", input_path);

    let docker_dir = match setup_docker_dir(input_path) {
        Ok(d) => d,
        Err(e) => {
            println!("Could create docker image from elf file: {:?}", e);
            std::process::exit(1);
        }
    };
    let docker_dir_path = docker_dir.path().to_str().map(|s| s.to_string());
    debug!("Created docker dir `{:?}`", docker_dir_path);

    let (_output_file, measurements) = match build_from_docker(&resource_path, "elf2eif", &docker_dir_path, output_path, &signing_certificate, &private_key) {
        Ok((o, m)) => {
            if let Err(_) = docker_dir.close() {
                debug!("Could not clean up docker directory `{:?}`", docker_dir_path)
            }
            (o, m)
        }
        Err(e) => {
            if let Err(_) = docker_dir.close() {
                debug!("Could not clean up docker directory `{:?}`", docker_dir_path)
            }
            println!("Building eif failed with {:?}", e);
            std::process::exit(1);
        }
    };

    println!("Enclave Image successfully created: `{}`", output_path);
    println!("{:#?}", measurements);
}
