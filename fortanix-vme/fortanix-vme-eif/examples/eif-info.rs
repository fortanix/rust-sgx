use clap::Parser;
use fortanix_vme_eif::{EifSectionType, FtxEif};
use std::io::Error as IoError;
use std::fs::{self, File};
use std::ops::Deref;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the eif file
    #[arg(short, long, value_name = "FILE")]
    enclave_path: PathBuf,

    /// Directory to extract info to
    #[arg(short, long, value_name = "DIR")]
    output_path: Option<PathBuf>,
}

fn store(mut output_path: PathBuf, filename: &str, content: &Vec<u8>) -> Result<(), IoError> {
    output_path.push(filename);
    fs::write(output_path, content)?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let eif = File::open(cli.enclave_path)
        .expect("Failed to open enclave");
    let mut eif = FtxEif::new(eif);

    let header = eif.eif_header()
        .expect("Failed to parse eif enclave");

    println!("[Header]");
    println!("  magic number: 0x{}", hex::encode(header.magic));
    println!("  eif version: {}", header.version);
    println!("  flags: {}", header.flags);
    println!("  default memory size: {}", header.default_mem);
    println!("  default #cpus: {}", header.default_cpus);
    println!("  # sections: {}", header.num_sections);
    println!("  reserved: {}", header.reserved);
    println!("  section offsets: {:?}", header.section_offsets);
    println!("  section size: {:?}", header.section_sizes);
    println!("  unused: {}", header.unused);
    println!("  crc32: {}", header.eif_crc32);

    for (sec_header, content) in eif.sections().expect("Failed to get section iterator") {
        println!("");
        println!("[Section Header]");
        println!("  Section type: {:?}", sec_header.section_type);
        println!("  flags: {:x}", sec_header.flags);
        println!("  section size: {}", sec_header.section_size);
        match sec_header.section_type {
            EifSectionType::EifSectionInvalid => (),
            EifSectionType::EifSectionKernel => {
                cli.output_path.as_ref().map(|p| store(p.clone(), "bzImage", &content));
            },
            EifSectionType::EifSectionCmdline => {
                if let Ok(cmd) = String::from_utf8(content.deref().clone()) {
                    println!("  content: \"{}\"", cmd);
                } else {
                    println!("  content: Failed to parse as an utf8 string");
                }
                cli.output_path.as_ref().map(|p| store(p.clone(), "cmdline", &content));
            },
            EifSectionType::EifSectionRamdisk => {
                cli.output_path.as_ref().map(|p| store(p.clone(), "initramfs.cpio.gz", &content));
            },
            EifSectionType::EifSectionSignature => {
                println!("  content: {:x?}", content);
                cli.output_path.as_ref().map(|p| store(p.clone(), "signature", &content));
            },
            EifSectionType::EifSectionMetadata => {
                if let Ok(meta) = String::from_utf8(content.deref().clone()) {
                    println!("  content: \"{}\"", meta);
                } else {
                    println!("  content: Failed to parse as an utf8 string");
                }
                cli.output_path.as_ref().map(|p| store(p.clone(), "metadata", &content));
            }
        }
    }
}
