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
                echo "You have a vsock loopback capable kernel, but the vsock_loopback module isn't loaded. Please run \'sudo modprobe vsock_loopback\'"
                exit -1
	    fi
        fi
    fi
}

function toolchain_version {
    toolchain_version="nightly-2021-09-08-x86_64-unknown-linux-gnu"
}

function has_tools {
    if [[ $(which musl-gcc) ]]; then
	echo "'musl-gcc' installed correctly"
    else
        echo "'musl-gcc' isn't found. Please run 'sudo apt install musl-tools'"
	exit -1
    fi
}

function determine_platform {
    if [[ -z "${NITRO_CLI_BLOBS}" ]]; then
        platform="linux"
    else
        platform="nitro"
    fi
}

function init {
    kernel_version
    has_vsock_loopback
    toolchain_version
    has_tools
    determine_platform
}

function compile {
    name=$1
    VME_TARGET="${TOOLCHAIN_DIR}/rust/rustup/toolchains/${toolchain_version}/lib/rustlib/x86_64-unknown-linux-fortanixvme/x86_64-unknown-linux-fortanixvme.json"
    CC=musl-gcc \
      RUSTFLAGS="-Clink-self-contained=yes" \
      cargo +${toolchain_version} build --locked --release --target ${VME_TARGET} -Zbuild-std

    # use elf as an output variable
    elf=${repo_root}/target/x86_64-unknown-linux-fortanixvme/release/${name}
}

function cargo_test {
    name=$1
    pushd ${repo_root}/fortanix-vme/tests/$name
    out=$(mktemp /tmp/$name.out.XXXXX)
    err=$(mktemp /tmp/$name.err.XXXXX)

    if [ -f ./test_interaction.sh ]; then
        ./test_interaction.sh &
	test_interaction=$!
    fi

    compile ${name}
    eif=$(mktemp /tmp/$name.eif.XXXXX)

    if [ "${platform}" == "nitro" ]; then
        elf2eif ${elf} ${eif}
	eif_runner ${eif} ${out} ${err}
        nitro-cli terminate-enclave --all

	out=$(tail +12 ${out})
	err=$(cat ${err} | grep -v "Start.*" || true)

	if [ "${out}" != "" ]; then
            echo "Test ${name} Failed"
	    echo "Got: ${out}"
            exit -1
	fi

	if [ "${err}" != "" ]; then
            echo "Test ${name} Failed"
	    echo "Got: ${err}"
            exit -1
        else
            echo "Success"
	fi
    else
        if [[ -v AWS_VM ]]; then
            elf2eif ${elf} ${eif}
            ssh ubuntu@${AWS_VM} "mkdir -p /home/ubuntu/ci-fortanixvme/${name}/"
            scp ${enclave_eif} ubuntu@${AWS_VM}:/home/ubuntu/ci-fortanixvme/${name}/
            if [ -f ./test_interaction.sh ]; then
                scp ./test_interaction.sh ubuntu@${AWS_VM}:/home/ubuntu/ci-fortanixvme/${name}/
            fi
        fi
	RUST_BACKTRACE=full ${elf} -- --nocapture > ${out} 2> ${err}

        out=$(cat ${out} | grep -v "^#" || true)
        expected=$(cat ./out.expected)

        if [ "${out}" == "${expected}" ]; then
            echo "Test ${name}: Success"
        else
            echo "Test ${name}: Failed"
	    echo "Got: ${out}"
            echo "Expected: ${expected}"
            exit -1
        fi
    fi

    if [ -f ./test_interaction.sh ]; then
        kill ${test_interaction}
    fi

    popd
}

function elf2eif {
    enclave_elf=$1
    enclave_eif=$2

    if [[ -z "${NITRO_RESOURCES}" ]]; then
        dir=$(mktemp -d /tmp/aws_cli.XXXXX)
        pushd ${dir}
        git clone https://github.com/aws/aws-nitro-enclaves-cli.git
        resources=${dir}/aws-nitro-enclaves-cli/blobs/x86_64
        NITRO_RESOURCES=${resources}
        popd
    else
        resources=${NITRO_RESOURCES}
    fi

    # Newly compiled ftxvme-elf2eif from this repo
    pushd ${repo_root}/fortanix-vme
    cargo run --bin ftxvme-elf2eif -- --input-file ${enclave_elf} --output-file ${enclave_eif} --resource-path ${resources} --verbose
    ls -lh ${enclave_eif}
    popd
}

function stop_enclaves {
    if [[ ${nitro_platform} -eq 1 ]]; then
        nitro-cli terminate-enclave --all || true
    fi
}

function eif_runner {
    enclave_eif=$1
    out=$2
    err=$3

    # Configure parent, if it hadn't been already
    nitro-cli-config -t 2 -m 512 > /dev/null 2> /dev/null || true

    nitro-cli describe-enclaves

    echo "running $1"
    # Run enclave
    nitro-cli run-enclave --eif-path ${enclave_eif} --cpu-count 2 --memory 512 --debug-mode > ${out} 2> ${err}
}
