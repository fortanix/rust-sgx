#! /bin/bash

# This requires the user to set appropritate runner in .cargo/config
set -ex
executable='target/x86_64-fortanix-unknown-sgx/debug/backtrace_panic'
cargo clean
cargo  +nightly run --target=x86_64-fortanix-unknown-sgx |  ../../scripts/stack-trace-resolve -e ${executable}
