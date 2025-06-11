use std::fs;
use std::io::Write;
use std::process::exit;

use nitro_cli::common::commands_parser::SignEifArgs;
use clap::{Arg, crate_authors, crate_version};
use env_logger;
use log::LevelFilter;

use eif_tools::*;

fn main() {
    let args = clap::App::new("eif-sign")
        .author(crate_authors!())
        .about("Sign an EIF file")
        .version(crate_version!())
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .help("Print extra information about the signing process"))
        .arg(Arg::with_name("input-eiffile")
            .short("i")
            .long("input-file")
            .required(true)
            .value_name("FILE")
            .validator_os(readable_file)
            .help("Path to input EIF file"))
        .arg(Arg::with_name("output-eiffile")
            .short("o")
            .long("output-file")
            .required(true)
            .value_name("FILE")
            .help("Path to output EIF file"))
        .arg(Arg::with_name("signing-certificate")
            .short("c")
            .long("signing-certificate")
            .required(true)
            .value_name("FILE")
            .validator_os(readable_file)
            .help("Path to signing certificate used to signed eif file"))
        .arg(Arg::with_name("private-key")
            .short("k")
            .long("private-key")
            .required(true)
            .value_name("FILE")
            .validator_os(readable_file)
            .help("Path to private key used to signed eif file"))
        .get_matches();

    let verbose = args.is_present("verbose");
    let input_path = args.value_of("input-eiffile").unwrap();
    let output_path = args.value_of("output-eiffile").unwrap();
    let signing_certificate = args.value_of("signing-certificate").unwrap();
    let private_key = args.value_of("private-key").unwrap();

    let mut logger = env_logger::Builder::from_default_env();
    let logger = logger.format(|buf, record| writeln!(buf, "{}", record.args()));
    if verbose {
        logger.filter_level(LevelFilter::Info).init();
    } else {
        logger.filter_level(LevelFilter::Error).init();
    }

    println!("Signing EIF file `{}` to `{}`, please wait", input_path, output_path);

    if let Err(e) = fs::copy(input_path, output_path) {
        println!("Failed to copy eif: {e}");
        exit(1);
    }

    let args = SignEifArgs {
        eif_path: output_path.to_string(),
        signing_certificate: Some(signing_certificate.to_string()),
        private_key: Some(private_key.to_string()),
    };
    match nitro_cli::sign_eif(args) {
        Ok(()) => println!("EIF successfully signed: `{}`", output_path),
        Err(e) => {
            println!("Error signing eif: {:#?}", e);
            exit(1);
        }
    }
}
