use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::exit;

use clap::{Arg, crate_authors, crate_version};
use env_logger;
use log::LevelFilter;
use nitro_cli::EifBuilder;
use sha2;
use sha2::Digest;

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

    let mut builder = match EifBuilder::from_eif_file(Path::new(input_path), sha2::Sha384::new()) {
        Ok(b) => b,
        Err(e) => {
            println!("Could not parse input EIF file: {:?}", e);
            exit(1);
        }
    };

    if builder.signature.is_some() {
        println!("Given EIF file is already signed");
        exit(1);
    }

    if let Err(e) = builder.set_sign_info(signing_certificate, private_key) {
        println!("Could not parse given certificate and key: {:?}", e);
        exit(1);
    };

    let mut output_file = File::create(output_path).expect("Could not create output file");
    let measurements = builder.write_to(&mut output_file);

    println!("EIF successfully signed: `{}`", output_path);
    println!("{:#?}", measurements);
}
