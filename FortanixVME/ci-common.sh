#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)

function kernel_version {
    kernel=$(uname -r)
    IFS='.' read -ra kernel <<< "${kernel}"

    kernel_major=${kernel[0]}
    kernel_minor=${kernel[1]}
}

function has_vsock_loopback {
    kernel_version
    vsock_loopback=0
    if [[ 5 -le ${kernel_major} ]]; then
        if [[ 6 -le ${kernel_minor} ]]; then
            if [[ $(lsmod | grep vsock_loopback) ]]; then
            vsock_loopback=1
            else
                echo "You have an vsock loopback capable kernel, but the vsock_loopback module isn't loaded. Please run \'sudo modprobe vsock_loopback\'"
                exit -1
	    fi
        fi
    fi
}

function toolchain_version {
    toolchain_version="nightly-2021-09-08-x86_64-unknown-linux-gnu"
}

function init {
    kernel_version
    has_vsock_loopback
    toolchain_version
}

function cargo_test {
    name=$1
    pushd ${repo_root}/FortanixVME/tests/$name
    out=$(mktemp /tmp/$name.out.XXXXX)
    err=$(mktemp /tmp/$name.err.XXXXX)

    if [ -f ./test_interaction.sh ]; then
        ./test_interaction.sh &
	test_interaction=$!
    fi

    VME_TARGET="${TOOLCHAIN_DIR}/rust/rustup/toolchains/${toolchain_version}/lib/rustlib/x86_64-unknown-linux-fortanixvme/x86_64-unknown-linux-fortanixvme.json"
    RUSTFLAGS="-Clink-self-contained=yes" \
      cargo +${toolchain_version} build --release --target ${VME_TARGET} -Zbuild-std
    RUSTFLAGS="-Clink-self-contained=yes" \
      cargo +${toolchain_version} run --release --target ${VME_TARGET} -Zbuild-std -- --nocapture > ${out} 2> ${err}

    if [ -f ./test_interaction.sh ]; then
        kill ${test_interaction}
    fi

    out=$(cat ${out} | grep -v "#")
    expected=$(cat ./out.expected)
    if [ "${out}" == "${expected}" ]; then
        echo "Test ${name}: Success"
    else
        echo "Test ${name}: Failed"
	echo "Got: ${out}"
	echo "Expected: ${expected}"
	exit -1
    fi
    popd
}

init
