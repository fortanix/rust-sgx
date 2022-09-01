#!/bin/bash -e

function install_toolchain {
    toolchain=$1

    if rustup show | grep -q "${toolchain}"; then
    	toolchain_installed=0
    else
	echo "Installing toolchain ${toolchain}"
        rustup install ${toolchain} >> /dev/null 2> /dev/null
        rustup +${toolchain} target add x86_64-fortanix-unknown-sgx >> /dev/null 2> /dev/null
    	toolchain_installed=1
    fi
}

function remove_toolchain {
    toolchain=$1

    if (test ${toolchain_installed} -eq 1); then
        rustup toolchain remove ${toolchain} >> /dev/null 2> /dev/null
    fi
}

function test_load_value_injection {
    elf=$1
    if objdump --disassemble=main ${elf} | grep -q lfence; then
        echo "Load value injection (LVI):                   [Ok]"
    else
        echo "Load value injection (LVI):                 [FAIL]"
    fi
}

function test_stale_data_reads_from_apic {
    elf=$1
    if readelf -s --wide ${elf} | grep -q copy_from_userspace; then
        echo "Stale Data reads from xAPIC (AEPIC Leak):     [Ok]"
    else
        echo "Stale Data reads from xAPIC (AEPIC Leak):   [FAIL]"
    fi
}

function test_stale_data_reads {
    elf=$1
    if readelf -s --wide ${elf} | grep -q copy_to_userspace; then
        echo "MMIO Stale Data reads:                        [Ok]"
    else
        echo "MMIO Stale Data reads:                      [FAIL]"
    fi
}

function test_mitigations {
    toolchain=$1
    cd `mktemp -d`

    echo "Testing toolchain ${toolchain}"

    # Install toolchain
    install_toolchain ${toolchain}

    # Create enclave
    cargo +${toolchain} new app >> /dev/null 2> /dev/null
    cd app
    cargo +${toolchain} build --target x86_64-fortanix-unknown-sgx >> /dev/null 2> /dev/null

    # Test mitigations
    test_load_value_injection target/x86_64-fortanix-unknown-sgx/debug/app
    test_stale_data_reads target/x86_64-fortanix-unknown-sgx/debug/app
    test_stale_data_reads_from_apic target/x86_64-fortanix-unknown-sgx/debug/app

    # Remove toolchain (if freshly installed)
    remove_toolchain ${toolchain}
}

function list_mitigations {
    echo "List mitigations"

    # Last toolchain without LVI
    test_mitigations nightly-2020-06-08
    # First toolchain with LVI
    test_mitigations nightly-2020-06-09
    echo ""

    # Last toolchain without MMIO Stale Data Reads
    test_mitigations nightly-2022-06-25
    # First toolchain with MMIO Stale Data Reads
    test_mitigations nightly-2022-06-26
    echo ""

    # Last toolchain with Stale Data Reads for xAPIC
    test_mitigations nightly-2022-08-20
    # First toolchain with Stale Data Reads for xAPIC
    test_mitigations nightly-2022-08-21
}

if (( $# == 0 )); then
    echo "Illegal number of parameters"
    echo "Usage: $0 test <toolchain>"
    echo "Usage: $0 list"
    exit -1
fi

if [ "$1" == "list" ]; then
    list_mitigations
    exit 0
fi

if [ "$1" == "test" ]; then
    test_mitigations $2
    exit 0
fi
