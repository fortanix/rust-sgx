use std::io::Cursor;
use std::path::Path;
use std::process::Command;
use std::{fs::File, path::PathBuf};

use anyhow::{anyhow, Context as _, Result};
use clap::{crate_authors, crate_version, Args, Parser};
use confidential_vm_blobs::{EFI_BOOT_STUB, INIT, KERNEL, maybe_vendored::MaybeVendoredImage};
use tempfile::NamedTempFile;

mod initramfs;

// TODO (RTE-740): deal with measurement/ID block/author key as part of CLI
/// Entry point for CLI application.
///
/// # Example
///
/// Under the following conditions:
/// * the user wants to use our vendored kernel image and efi boot stub rather than their own
/// * a statically compiled application is available at `/tmp/application`
/// * the `ukify` binary is available in the user's `PATH`
///
/// the following invocation will create a UKI image at the specified output path:
///
/// ```sh
/// elf2uki \
/// --app /tmp/application \
/// --output image-to-test.efi
/// ```
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

    #[arg(
        long = "kernel",
        help = "Path to the kernel image file, defaulting to the vendored kernel blob if not provided",
        value_name = "FILE"
    )]
    kernel_image_path: Option<PathBuf>,

    #[arg(
        long = "efi-stub",
        help = "Path to the EFI boot stub file, defaulting to the vendored boot stub blob if not provided",
        value_name = "FILE"
    )]
    efi_stub_path: Option<PathBuf>,
}

struct ValidatedCli {
    non_defaulted_args: NonDefaultedArgs,
    output_path: PathBuf,
    kernel_image: MaybeVendoredImage,
    efi_stub_image: MaybeVendoredImage,
}

#[derive(Args, Debug)]
struct NonDefaultedArgs {
    #[arg(
        long = "app",
        help = "Path to the application elf file",
        value_name = "FILE"
    )]
    application_elf_path: PathBuf,

    #[arg(
        long = "cmdline",
        help = "String to pass as the kernel command line",
        value_name = "STRING"
    )]
    kernel_cmdline: Option<String>,
}


pub fn open_file(path: &Path) -> Result<File> {
    File::open(path).with_context(|| format!("failed to open file at path {}", path.display()))
}

impl Cli {
    /// Validate the provided values, filling in defaults where necessary
    fn validate(self) -> Result<ValidatedCli> {
        let Cli {
            output_path,
            non_defaulted_args,
            kernel_image_path,
            efi_stub_path,
        } = self;

        let kernel_image = match kernel_image_path {
            Some(path) => MaybeVendoredImage::from(path),
            None => MaybeVendoredImage::from_vendored(KERNEL)?,
        };

        let efi_stub_image = match efi_stub_path {
            Some(path) => MaybeVendoredImage::from(path),
            None => MaybeVendoredImage::from_vendored(EFI_BOOT_STUB)?,
        };

        // Check susceptible to TOCTOU, but try to error out early and clearly if files
        // cannot be opened
        for path in [
            kernel_image.path(),
            &non_defaulted_args.application_elf_path,
            efi_stub_image.path(),
        ] {
            let _ = open_file(path)?;
        }

        let output_path = output_path.unwrap_or_else(|| kernel_image.path().join(".efi"));

        Ok(ValidatedCli {
            non_defaulted_args,
            output_path,
            kernel_image,
            efi_stub_image,
        })
    }
}

/// Run the `ukify` tool after validation of the passed-in arguments
fn build_uki(cli: &ValidatedCli, initramfs_path: &Path) -> Result<()> {
    const UKIFY_EXECUTABLE: &str = "ukify";
    let mut command = Command::new(UKIFY_EXECUTABLE);
    command
        .arg("build")
        .arg("--linux")
        .arg(cli.kernel_image.path())
        .arg("--initrd")
        .arg(initramfs_path)
        .arg("--stub")
        .arg(&cli.efi_stub_image.path())
        .arg("--output")
        .arg(&cli.output_path);

    if let Some(cmdline) = &cli.non_defaulted_args.kernel_cmdline {
        command.arg("--cmdline").arg(cmdline);
    }

    let output = command.output().map_err(|e| {
        let error_kind = e.kind();
        anyhow::Error::new(e).context(match error_kind {
            std::io::ErrorKind::NotFound => {
                "`ukify` tool not found in PATH; make it available or install `systemd-ukify`"
            }
            _ => "spawning ukify process failed",
        })
    })?;
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
    let init = Cursor::new(INIT);

    // Unfortunately `ukify` forces us to have data in files.
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
