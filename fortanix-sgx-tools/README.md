# libenclave-tools

Two tools are currently included in this package. `link-sgxs` will link a
static libray based on `libenclave` and convert it to an SGXS file.
`cargo-build-enclave` is a `cargo` subcommand that will run `cargo build` and
then `link-sgxs`.

See also the [Quick start guide](../doc/GUIDE.md).

Compiles with Rust nightly.
