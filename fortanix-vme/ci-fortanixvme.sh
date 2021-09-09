#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)
cd ${repo_root}/fortanix-vme

source ./ci-common.sh

function cleanup {
    stop_runner
}

function setup_environment {
    if [[ -z "${TOOLCHAIN_DIR}" ]]; then
        echo 'The `TOOLCHAIN_DIR` environment variable isnt set. Make sure to source the `shell/env` script from the toolchain repo'
        exit -1
    fi
    trap cleanup err
    trap cleanup exit
    cargo +${toolchain_version} clean
}

function test_runner {
    pushd enclave-runner
    cargo +${toolchain_version} test
    popd
}

function start_runner {
    pushd enclave-runner
    cargo +${toolchain_version} run &
    pid_runner=$!
    popd
}

function stop_runner {
    if [[ ${pid_runner} -ne 0 ]]; then
        echo "Stopping enclave runner"
        kill ${pid_runner}
	pid_runner=0
    fi
}

function run_tests {
    tests=$@

    setup_environment

    if [[ ${vsock_loopback} -eq 1 ]]; then
        start_runner
        for name in ${tests}
        do
            cargo_test $name
        done
        stop_runner
    else
        echo "vsock loopback device not available, skipping these tests"
    fi
}

test_runner
run_tests outgoing_connection 

echo "********************************"
echo "**    All tests succeeded!    **"
echo "********************************"
