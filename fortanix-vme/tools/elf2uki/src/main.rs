use std::path::Path;
use std::process::Command;
use std::{fs::File, path::PathBuf};

use anyhow::{anyhow, Context as _, Ok, Result};
use clap::{Args, Parser};
use confidential_vm_blobs::{EFI_BOOT_STUB_PATH, INIT_PATH, KERNEL_PATH};
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
#[command(version, author)]
#[command(
    about = "Assemble UKI files from their constituents",
    long_about = "Receive paths to the different building blocks of a UKI file as input, and output the resulting UKI file"
)]
struct Cli {
    #[command(flatten)]
    args_without_validation: ArgsWithoutValidation,

    /// Path where the newly created UKI file will be written.
    ///
    /// Equal to the kernel image path appended with `.efi` if not specified
    #[arg(short, long = "output", value_name = "FILE")]
    output_path: Option<PathBuf>,
}

struct ValidatedCli {
    args_without_validation: ArgsWithoutValidation,
    output_path: PathBuf,
}

#[derive(Args, Debug)]
struct ArgsWithoutValidation {
    /// Path to the application elf file
    #[arg(long = "app", value_name = "FILE")]
    application_elf_path: PathBuf,

    /// String to pass as the kernel command line
    #[arg(
        long = "cmdline",
        value_name = "STRING",
        default_value = "console=ttyS0 earlyprintk=serial" // TODO(RTE-804): unnecessary under new ABI
    )]
    kernel_cmdline: String,

    /// Path to the kernel image file
    #[arg(long = "kernel", value_name = "FILE", default_value=KERNEL_PATH)]
    kernel_image_path: PathBuf,

    /// Path to the EFI boot stub file, defaulting to the vendored boot stub blob if not provided
    #[arg(long = "efi-stub", value_name = "FILE", default_value=EFI_BOOT_STUB_PATH)]
    efi_boot_stub_path: PathBuf,
}

pub fn open_file<P: AsRef<Path>>(path: P) -> Result<File> {
    let path = path.as_ref();
    File::open(path).with_context(|| format!("failed to open file at path {}", path.display()))
}

fn append_to_file_name(mut path_buf: PathBuf, append: &str) -> Result<PathBuf> {
    let mut extended_name = path_buf.file_name().ok_or_else(|| anyhow!("path {path_buf:?} unexpectedly has no file name"))?.to_owned();
    extended_name.push(append);
    path_buf.set_file_name(extended_name);
    Ok(path_buf)
}

impl Cli {
    /// Validate the provided values, filling in defaults where necessary
    fn validate(self) -> Result<ValidatedCli> {
        let Cli {
            output_path,
            args_without_validation,
        } = self;

        // Check susceptible to TOCTOU, but try to error out early and clearly if files
        // cannot be opened
        for path in [
            &args_without_validation.kernel_image_path,
            &args_without_validation.application_elf_path,
            &args_without_validation.efi_boot_stub_path,
        ] {
            let _ = open_file(path)?;
        }

        let output_path = match output_path {
            Some(output_path) => output_path,
            None => append_to_file_name(args_without_validation.kernel_image_path.clone(), ".efi")?,
        };

        Ok(ValidatedCli {
            args_without_validation,
            output_path,
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
        .arg(&cli.args_without_validation.kernel_image_path)
        .arg("--initrd")
        .arg(initramfs_path)
        .arg("--stub")
        .arg(&cli.args_without_validation.efi_boot_stub_path)
        .arg("--output")
        .arg(&cli.output_path);

    command
        .arg("--cmdline")
        .arg(&cli.args_without_validation.kernel_cmdline);

    let output = command.output().context("spawning ukify process failed")?;
    if !output.status.success() {
        return Err(anyhow!(
            "ukify exited with non-zero status code and stdout : {} \n\n stderr : {}",
            String::from_utf8(output.stdout).context("ukify stdout is non-utf8")?,
            String::from_utf8(output.stderr).context("ukify stderr is non-utf8")?,
        ));
    }
    Ok(())
}

fn main() -> Result<()> {
    confidential_vm_blobs::check_confidential_vm_blobs_dependencies()?;
    let args = Cli::parse();
    let validated_args = args.validate()?;

    let application_elf = open_file(&validated_args.args_without_validation.application_elf_path)?;
    let init = open_file(INIT_PATH)?;

    // Unfortunately `ukify` forces us to have data in files.
    let mut initramfs_file = NamedTempFile::new().context("failed to create initramfs file")?;
    initramfs_file = initramfs::build(application_elf, init, initramfs_file)
        .context("failed to create initramfs")?;

    build_uki(&validated_args, initramfs_file.path())?;

    println!(
        "Confidential VM Image successfully created at path: `{}`",
        validated_args.output_path.display()
    );
    Ok(())
}
