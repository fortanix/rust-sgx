# SGXS library

## Format

SGXS is the SGX stream format. This is a cross-platform file format to describe 
SGX enclaves. For more information about the format itself, see the [format 
specification](../doc/SGXS.md).

## Rust crate

The crate provides a library with an abstraction over the SGXS format as well
as an API to deal with the SGX Linux ioctl driver, as well as several utilities
built on top of the library.

Compiles with Rust nightly.

## Tools

See the [sgxs-tools crate](../sgxs-tools) for utilities that use this library.
