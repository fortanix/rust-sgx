# Quick start guide 

This guide will get you started building SGX secure enclaves in Rust using the
Fortanix Rust SGX development platform.

## Prerequisites

Make sure to have the following installed:

- Rust **nightly** and Cargo (e.g. from https://www.rust-lang.org/downloads.html)
- `ld.gold` from binutils 2.26. Neither <=2.25 nor 2.27 work at this time.
- Intel SGX PSW and driver from [01.org](https://01.org/intel-software-guard-extensions).

## Install needed tools

```sh
$ cargo install fortanix-sgx-tools
$ cargo install sgxs-tools
```

Cargo will put the tools in `~/.cargo/bin`, so make sure to add that directory 
to your `PATH`:

```sh
$ export PATH=$PATH:~/.cargo/bin
```

## Build your first enclave

TODO...
