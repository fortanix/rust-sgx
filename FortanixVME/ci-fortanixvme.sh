#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)
cd ${repo_root}/FortanixVME

function cleanup {
    echo "Stopping enclave runner"
    kill $pid_runner
}

function setup_environment {
    if [[ -z "${TOOLCHAIN_DIR}" ]]; then
        echo 'The `TOOLCHAIN_DIR` environment variable isnt set. Make sure to source the `shell/env` script from the toolchain repo'
        exit -1
    fi
    trap cleanup err
    trap cleanup exit
    cargo clean
}

function test_runner {
    pushd enclave-runner
    cargo test
    popd
}

function start_runner {
    pushd enclave-runner
    cargo build
    cargo run -- --tcp &
    pid_runner=$!
    popd
}

function cargo_test {
    name=$1
    pushd tests/$name
    VME_TARGET="${TOOLCHAIN_DIR}/rust/rustup/toolchains/nightly-2021-09-08-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-fortanixvme/x86_64-unknown-linux-fortanixvme.json"
    RUSTFLAGS="-Clink-self-contained=yes" \
      cargo test --release --target ${VME_TARGET} -Zbuild-std -- --nocapture
    popd
}

test_runner
setup_environment
start_runner
cargo_test tcp_connection
