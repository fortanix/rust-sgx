# tdx-isa

Rust wrapper crate for TDX attestation structures and functions from the
[`tdx-attest-rs`](https://github.com/intel/confidential-computing.tee.dcap/tree/main/QuoteGeneration/quote_wrapper/tdx-attest-rs)
dependency.

## Build dependencies

- `libtdx-attest-dev` DEB package on Ubuntu. You can use
  [install_build_deps.sh](../../install_build_deps.sh) for convenience.
- This crate depends on
  [`tdx-attest-sys`](https://github.com/intel/confidential-computing.tee.dcap/tree/main/QuoteGeneration/quote_wrapper/tdx-attest-sys),
  which expects the system TDX attest headers and library. On Debian/Ubuntu,
  `libtdx-attest-dev` provides the headers (and depends on `libtdx-attest`).
  `libtdx-attest` provides the library.
- `SGX_SDK` environment variable (optional): This variable is read by
  [`tdx-attest-sys`](https://github.com/intel/confidential-computing.tee.dcap/tree/main/QuoteGeneration/quote_wrapper/tdx-attest-sys)
  to locate the header for generating Rust bindings. It expects
  `$SGX_SDK/include/tdx_attest.h`.
