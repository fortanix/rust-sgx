#!/bin/bash

pushd $(dirname "${BASH_SOURCE[0]})")

export CFLAGS_x86_64_fortanix_unknown_sgx="-isystem/usr/include/x86_64-linux-gnu -mlvi-hardening -mllvm -x86-experimental-lvi-inline-asm-hardening"
export CC_x86_64_fortanix_unknown_sgx=clang-11

cargo build --target=x86_64-fortanix-unknown-sgx

popd
