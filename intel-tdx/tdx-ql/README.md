# tdx-isa

Rust wrapper crate for TDX attestation structures and functions. It supports
two backends:

- `ioctl` (default): uses `/dev/tdx_guest` via `nix` ioctls.
- `tdx-module`: uses
  [`tdx-attest-rs`](https://github.com/intel/confidential-computing.tee.dcap/tree/main/QuoteGeneration/quote_wrapper/tdx-attest-rs). It still requries `/dev/tdx_guest`.

## Build dependencies

- `ioctl` backend (default): no additional build dependencies beyond Rust and
  `nix`.
- `tdx-module` backend: requires the system TDX attest headers and library via
  `libtdx-attest-dev` on Debian/Ubuntu. You can use
  [install_build_deps.sh](../../install_build_deps.sh) for convenience.
- `tdx-module` backend: `tdx-attest-sys` expects the header at
  `$SGX_SDK/include/tdx_attest.h`. Set `SGX_SDK` if the headers are not in a
  standard location. This is not needed for the `ioctl` backend.
