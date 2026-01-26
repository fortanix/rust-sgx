use std::io::Cursor;
use std::path::Path;
use std::process::Command;
use std::{fs::File, path::PathBuf};

use anyhow::{anyhow, Context as _, Result};
use clap::{crate_authors, crate_version, Args, Parser};
use tempfile::NamedTempFile;

mod initramfs;

const UKIFY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/ukify.py");
const INIT_BLOB: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/blobs/init"));

// TODO (RTE-740): deal with measurement/ID block/author key as part of CLI
#[derive(Parser, Debug)]
#[command(name = "Elf2Uki")]
#[command(version = crate_version!())]
#[command(author = crate_authors!())]
#[command(
    about = "Assemble UKI files from their constituents",
    long_about = "Receive paths to the different building blocks of a UKI file as input, and output the resulting UKI file"
)]
struct Cli {
    #[command(flatten)]
    non_defaulted_args: NonDefaultedArgs,

    #[arg(
        short,
        long = "output",
        help = "Path where the newly created UKI file will be written. Equal to the kernel image path appended with `.efi` if not specified",
        value_name = "FILE"
    )]
    output_path: Option<PathBuf>,
}

struct ValidatedCli {
    non_defaulted_args: NonDefaultedArgs,
    output_path: PathBuf,
}

#[derive(Args, Debug)]
struct NonDefaultedArgs {
    #[arg(
        long = "kernel",
        help = "Path to the kernel image file",
        value_name = "FILE"
    )]
    kernel_image_path: PathBuf,

    #[arg(
        long = "app",
        help = "Path to the application elf file",
        value_name = "FILE"
    )]
    application_elf_path: PathBuf,

    #[arg(
        long = "uefi-stub",
        help = "Path to the UEFI stub file",
        value_name = "FILE"
    )]
    // This is a required argument because `ukify` uses '/usr/lib/systemd/boot/efi/linux{opts.efi_arch}.efi.stub' by default, but this is not behavior we want to fall back on
    uefi_stub_path: PathBuf,

    #[arg(
        long = "cmdline",
        help = "String to pass as the kernel command line",
        value_name = "STRING"
    )]
    kernel_cmdline: Option<PathBuf>,
}

pub fn open_file(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("failed to open file at path {}", path.display()))
}

impl Cli {
    /// Validate the provided values, filling in defaults where necessary
    fn validate(self) -> Result<ValidatedCli> {
        let output_path = self
            .output_path
            .unwrap_or_else(|| self.non_defaulted_args.kernel_image_path.join(".efi"));

        // Check susceptible to TOCTOU, but try to error out early and clearly if files
        // cannot be opened
        for path in [
            &self.non_defaulted_args.kernel_image_path,
            &self.non_defaulted_args.application_elf_path,
            &self.non_defaulted_args.uefi_stub_path,
        ] {
            let _ = open_file(path)?;
        }

        Ok(ValidatedCli {
            non_defaulted_args: self.non_defaulted_args,
            output_path,
        })
    }
}

/// Run the `ukify` tool after validation of the passed-in arguments
fn build_uki(cli: &ValidatedCli, initramfs_path: &Path) -> Result<()> {
    let mut command = Command::new(UKIFY_PATH);
    command
        .arg("build")
        .arg("--linux")
        .arg(&cli.non_defaulted_args.kernel_image_path)
        .arg("--initrd")
        .arg(initramfs_path)
        .arg("--stub")
        .arg(&cli.non_defaulted_args.uefi_stub_path)
        .arg("--output")
        .arg(&cli.output_path);

    if let Some(cmdline) = &cli.non_defaulted_args.kernel_cmdline {
        command.arg("--cmdline").arg(cmdline);
    }

    if let Some(cmdline) = &cli.non_defaulted_args.kernel_cmdline {
        command.arg("--cmdline").arg(cmdline);
    }

    let output = command.output().context("spawning ukify process failed")?;
    if !output.status.success() {
        return Err(anyhow!(
            "ukify exited with non-zero status code and stdout : {} \n\n sterr : {}",
            String::from_utf8(output.stdout).context("ukify stdout is non-utf8")?,
            String::from_utf8(output.stderr).context("ukify stderr is non-utf8")?,
        ));
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let validated_args = args.validate()?;

    let application_elf = open_file(&validated_args.non_defaulted_args.application_elf_path)?;
    let init = Cursor::new(INIT_BLOB);

    // Unfortunately `aws_nitro_enclaves_image_format::EifBuilder` forces us to have data in
    // files.
    let mut initramfs_file = NamedTempFile::new().context("failed to create initramfs file")?;
    initramfs_file = initramfs::build(application_elf, init, initramfs_file)
        .context("failed to create initramfs")?;

    build_uki(&validated_args, initramfs_file.path())?;

    println!(
        "Enclave Image successfully created at path: `{}`",
        validated_args.output_path.display()
    );
    Ok(())
}
