# SGXS utilites

## Format

SGXS is the SGX stream format. This is a cross-platform file format to describe 
SGX enclaves. For more information about the format itself, see the [format 
specification](../doc/SGXS.md).

## Rust crate

The crate provides a library with an abstraction over the SGXS format as well
as an API to deal with the SGX Linux ioctl driver, as well as several utilities
built on top of the library.

Compiles with Rust nightly.

## sgxs-info

The `sgxs-info` parses SGXS files for further analysis. It currently supports the following commands:

### list-all

The most verbose listing format, which lists all the individual commands
contained the input file, including their parameters. For EEXTEND commands,
data is as either `(empty)` if the data is all zeroes, `[byte]*` if the data is
all the same value `byte`, or `(data)` in any other case.

This is the only command that can read non-canonical SGXS files.

### list-pages

This listing format lists all commands, except EEXTEND commands. The EEXTEND
information is consolidated in the preceding EADD command. The data is
displayed in the same format as in the `list-all` command. The `measured` field
indicates which part of the page are being measured by an EEXTEND command:
`all`, `partial` or `none`.

### info

This command gives a summarized overview of all the different sections in
memory. The entire memory indicated by the enclave size is described.
Consecutive pages that have the same type, flags, data and measurement fields
are consolidated into a single line. Unmapped pages are indicated as such.

### dump-mem

This command dumps the memory of the enclave as it would be seen before
executing an EENTER instruction. Unmapped pages in between sections are filled
with zeroes. Unmapped pages at the end are truncated.

## sgxs-load

The `sgxs-load` loads an SGXS file into the EPC. Currently, only the linux
ioctl driver is supported. You must also provide a signature and initialization
token.
