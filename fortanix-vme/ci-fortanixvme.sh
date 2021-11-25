#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)
cd ${repo_root}/fortanix-vme

# Options:
# AWS_VM: When this environment variable is set, binaries will be sent to this AWS VM
# NITRO_RESOURCES: The location of the nitro resources (e.g., kernel, ...) required for
#                    the elf2eif tool. When this environment variable isn't set, the 
#                    resources will be downloaded

source ./ci-common.sh
init

function cleanup {
    stop_runner
    killall test_interaction
}

function setup_environment {
    if [[ -z "${TOOLCHAIN_DIR}" ]]; then
        echo 'The `TOOLCHAIN_DIR` environment variable isnt set. Make sure to source the `shell/env` script from the toolchain repo'
        exit -1
    fi
    trap cleanup err
    trap cleanup exit
    cargo +${toolchain_version} --locked clean
}

function start_runner {
    pushd fortanix-vme-runner
    cargo +${toolchain_version} --locked build
    cargo +${toolchain_version} --locked run &

    if [[ -v AWS_VM ]]; then
        ssh ubuntu@${AWS_VM} 'mkdir -p /home/ubuntu/ci-fortanixvme'
        scp ${repo_root}/target/debug/fortanix-vme-runner  ubuntu@${AWS_VM}:/home/ubuntu/ci-fortanixvme
    fi

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

run_tests\
    hello_world \
    outgoing_connection \
    incoming_connection \
    iron

echo "********************************"
echo "**    All tests succeeded!    **"
echo "********************************"
