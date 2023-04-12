use clap::Parser;
use fortanix_vme_eif::Builder;
use std::io::{BufReader, BufWriter, Cursor, Write};
use std::fs::File;
use std::path::PathBuf;

const KERNEL: &'static [u8; 5083088] = include_bytes!("../data/bzImage");
const KERNEL_CONFIG: &'static str = include_str!("../data/bzImage.config");
const NSM: &'static [u8; 20504] = include_bytes!("../data/nsm.ko");
const INIT: &'static [u8; 742968] = include_bytes!("../data/init");
const CMDLINE: &'static str = include_str!("../data/cmdline");

#[derive(Parser, Debug)]
#[command(about = "Convert an x86_64-unknown-linux-fortanixvme ELF binary to an AWS EIF file")]
#[command(author, version, long_about = None)]
struct Cli {
    /// Path to the elf file
    #[arg(short, long, value_name = "FILE")]
    elf_path: PathBuf,

    /// Path where the resulting EIF file should be written
    #[arg(short, long, value_name = "FILE")]
    output_path: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let elf = File::open(cli.elf_path)
        .expect("Failed to open elf path");
    let elf = BufReader::new(elf);
    let eif = File::create(cli.output_path)
        .expect("Failed to open output path");
    let eif = BufWriter::new(eif);
    let init = Cursor::new(INIT);
    let nsm = Cursor::new(NSM);
    let kernel = Cursor::new(KERNEL);
    let kernel_config = Cursor::new(KERNEL_CONFIG);
    
    Builder::new(elf, init, nsm, kernel, kernel_config, CMDLINE.trim())
        .build(eif)
        .expect("Failed to create eif file")
        .into_inner()
        .flush()
        .expect("Failed to flush remaining data to eif file");
}
