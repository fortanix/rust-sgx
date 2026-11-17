use aws_nitro_blobs::{CMDLINE_PATH, INIT_PATH, KERNEL_CONFIG_PATH, KERNEL_PATH, NSM_PATH};
use clap::Parser;
use fortanix_vme_eif::Builder;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(about = "Convert an x86_64-unknown-linux-fortanixvme ELF binary to an AWS EIF file")]
#[command(author, version, long_about = None)]
struct Cli {
    /// Path to the elf file
    #[arg(short, long, value_name = "FILE")]
    elf_path: PathBuf,

    #[arg(short, long, value_name = "NAME")]
    name: Option<String>,

    /// Path where the resulting EIF file should be written
    #[arg(short, long, value_name = "FILE")]
    output_path: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let elf = File::open(cli.elf_path.to_owned()).expect("Failed to open elf path");
    let elf = BufReader::new(elf);
    let eif = File::create(cli.output_path).expect("Failed to open output path");
    let eif = BufWriter::new(eif);

    let init = File::open(INIT_PATH).expect(&format!("Failed to open {}", INIT_PATH));
    let nsm = File::open(NSM_PATH).expect(&format!("Failed to open {}", NSM_PATH));
    let kernel = File::open(KERNEL_PATH).expect(&format!("Failed to open {}", KERNEL_PATH));
    let kernel_config =
        File::open(KERNEL_CONFIG_PATH).expect(&format!("Failed to open {}", KERNEL_CONFIG_PATH));
    let cmdline = fs::read(CMDLINE_PATH).expect(&format!("Failed to read {}", CMDLINE_PATH));
    let cmdline = str::from_utf8(&cmdline).expect("invalid cmdline content");
    let name = cli
        .name
        .or_else(|| {
            Path::new(&cli.elf_path)
                .file_name()
                .map(|name| name.to_str().map(|name| name.to_string()))
                .flatten()
        })
        .unwrap_or(String::from("FtxEnclave"));

    Builder::new(name, elf, init, nsm, kernel, kernel_config, cmdline.trim())
        .build(eif)
        .expect("Failed to create eif file")
        .into_inner()
        .flush()
        .expect("Failed to flush remaining data to eif file");
}
