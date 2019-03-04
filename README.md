# Fortanix Rust Enclave Development Platform

[![Runtime Encryption Slack](https://img.shields.io/badge/Slack-%23rust--sgx-blue.svg?logo=slack&logoColor=whitesmoke)](https://fortanix.com/runtime-encryption-slack) [![Build Status](https://travis-ci.com/fortanix/rust-sgx.svg?branch=master)](https://travis-ci.com/fortanix/rust-sgx)

The [Fortanix Rust EDP](https://edp.fortanix.com/) is the preferred way to write Intel SGX enclaves from scratch.

## [Get started now.](https://edp.fortanix.com/docs/installation/guide/)

```sh
# Install EDP components
rustup target add x86_64-fortanix-unknown-sgx --toolchain nightly
cargo install fortanix-sgx-tools sgxs-tools
echo >> ~/.cargo/config -e '[target.x86_64-fortanix-unknown-sgx]\nrunner = "ftxsgx-runner-cargo"'

# Check your SGX setup
sgx-detect

# Run your enclave!
cargo new --bin hello-world
cd hello-world
cargo run --target x86_64-fortanix-unknown-sgx
```

[Documentation](https://edp.fortanix.com/docs/)

Looking for the in-enclave source code? Check out the [rust-lang/rust
repository](https://github.com/rust-lang/rust/tree/master/src/libstd/sys/sgx).

# Contributing

We gratefully accept contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).

Here are some ways to contribute:

1. Participate in the `#rust-sgx` channel of the [Runtime Encryption community on Slack](https://fortanix.com/runtime-encryption-slack).
2. File [bug reports](https://github.com/fortanix/rust-sgx/issues/new).
3. Help design [new features](https://github.com/fortanix/rust-sgx/issues?q=is%3Aopen+is%3Aissue+label%3Aneeds-design).
4. Contribute code via [pull requests](https://github.com/fortanix/rust-sgx/pulls).

All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
