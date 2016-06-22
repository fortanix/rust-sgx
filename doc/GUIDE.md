# Quick start guide 

This guide will get you started building SGX secure enclaves in Rust using 
`libenclave` and `sgxs-tools`.

## Prerequisites

Make sure to have the following installed:

- Rust **nightly** and Cargo (e.g. from https://www.rust-lang.org/downloads.html)
- `ld.gold` from binutils 2.26 or higher
- SGX linux driver from [this repository](../isgx)

And have the following ready:

- Intel Windows SGX PSW. This might come preinstalled or as part of a driver
  package.

## Install needed tools

```sh
$ cargo install cargo-clone
$ cargo install libenclave-tools
$ cargo install sgxs-tools
```

Cargo will put the tools in `~/.cargo/bin`, so make sure to add that directory 
to your `PATH`:

```sh
$ export PATH=$PATH:~/.cargo/bin
```

## Convert Launch Enclave

Find `le.signed.dll` and `le_prod_css.bin` from your Windows installation, or 
you can extract them from the installer package using e.g. `7z`. Convert the 
DLL to SGXS format:

```sh
$ pe2sgxs le.signed.dll le.sgxs
```

Store `le.sgxs` and `le_prod_css.bin` is some convenient place, you will need 
these files every time you want to run an enclave. Read [my blog 
post](https://jbeekman.nl/blog/2015/10/intel-has-full-control-over-sgx/) for 
reasons why.

## Build your own enclave

We're ready to roll! Let's download the example enclave and try to run it:

```sh
$ cargo clone enclave-example
$ mv enclave-example trusted
$ cargo clone enclave-example-runner
$ mv enclave-example-runner untrusted
$ cd trusted
$ cargo build-enclave -H 0x10000 -S 0x10000
$ cd target/debug
$ openssl genrsa -3 3072 > private.pem
$ sgxs-sign --key private.pem -d enclave_example.sgxs enclave_example.sig
$ cd ../../../untrusted
$ cargo build
$ target/debug/enclave-runner ../trusted/target/debug/enclave_example.sgxs ../trusted/target/debug/enclave_example.sig /path/to/le.sgxs /path/to/le_prod_css.bin
```

If everything went well, you should see the following output:

```
Usercall: 2 3 4 5 6
Enclave returned: 5678
```

Congratulations, you have compiled Rust code and run it in enclave mode using 
SGX! You can of course modify the source in the `trusted/` and `untrusted/`
directories to do whatever you want.
