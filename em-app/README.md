# Fortanix Enclave Manager application library

This crate provides utility functions for Fortanix Enclave Manager.
Currently it allows obtaining signed certificates for SGX and AWS Nitro enclaves running in Enclave Manager environment.

To build for SGX:
```
export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11

cargo build --target=x86_64-fortanix-unknown-sgx --locked
```

To build for Nitro, use either of the following
```
cargo build --target=x86_64-unknown-linux-musl --locked
cargo build --target=x86_64-unknown-linux-gnu --locked
cargo build --target=x86_64-unknown-linux-fortanixvme --locked
```

Patches might need to be applied, these are available on root level Cargo.toml.
