# libenclave-tools

Two tools are currently included in this package. `link-sgxs` will link a
static libray based on `libenclave` and convert it to an SGXS file.
`cargo-build-enclave` is a `cargo` subcommand that will run `cargo build` and
then `link-sgxs`.

See also the [Quick start guide](../doc/GUIDE.md).

Compiles with Rust nightly.

## What's the deal with the licensing?

The intention of `link-sgxs` is that you use it to link enclaves you've written
using `libenclave`. `libenclave` is licensed under the AGPL, so you will need
to license those enclaves under AGPL as well. `link-sgxs` includes some AGPL
code in all output enclaves, which is not an issue if you use it with
`libenclave`, but it could be if you link enclaves not based on `libenclave`.
You are of course free to modify `link-sgxs` to no longer link with that file
(`src/entry.S`), which would eliminate the AGPL licensing requirement from that
file. `link-sgxs` itself is licensed under the GPL.
