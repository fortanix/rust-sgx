use blobs_tool::download::download_blobs;
use clap::{Command, arg, command, value_parser};
use std::path::PathBuf;

fn main() {
    env_logger::init();
    let matches = command!()
        .subcommand(
            Command::new("download")
                .about("Download aws nitro blobs")
                .arg(
                    arg!(
                        -o --output <directory> "Sets the output directory (must exist)"
                    )
                    .required(false)
                    .value_parser(value_parser!(PathBuf)),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("download") {
        let default_output = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));
        let output = matches
            .get_one::<PathBuf>("output")
            .unwrap_or(&default_output);
        download_blobs(output.as_path()).unwrap();
    }
}
