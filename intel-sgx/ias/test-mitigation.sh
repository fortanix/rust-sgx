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
    toolchain=$2
    if objdump --disassemble=main ${elf} | grep -q lfence; then
        out="mitigated"
        echo "Load value injection (LVI):                   [Ok] ${toolchain}"
    else
        out="not mitigated"
        echo "Load value injection (LVI):                 [FAIL] ${toolchain}"
    fi
}

function test_stale_data_reads_from_apic {
    elf=$1
    toolchain=$2
    if readelf -s --wide ${elf} | grep -q copy_from_userspace; then
        echo "Stale Data reads from xAPIC (AEPIC Leak):     [Ok] ${toolchain}"
    else
        echo "Stale Data reads from xAPIC (AEPIC Leak):   [FAIL] ${toolchain}"
    fi
}

function test_stale_data_reads {
    elf=$1
    toolchain=$2
    if readelf -s --wide ${elf} | grep -q copy_to_userspace; then
        echo "MMIO Stale Data reads:                        [Ok] ${toolchain}"
    else
        echo "MMIO Stale Data reads:                      [FAIL] ${toolchain}"
    fi
}

function build_enclave {
    toolchain=$1

    dir=`mktemp -d`
    pushd ${dir} >> /dev/null
    cargo +${toolchain} new app >> /dev/null 2> /dev/null
    pushd app >> /dev/null
    cargo +${toolchain} build --target x86_64-fortanix-unknown-sgx >> /dev/null 2> /dev/null
    popd >> /dev/null
    popd >> /dev/null
    out=${dir}/app/target/x86_64-fortanix-unknown-sgx/debug/app
}

function test_mitigations {
    toolchain=$1

    echo "Testing toolchain ${toolchain}"

    # Install toolchain
    install_toolchain ${toolchain}

    # Create enclave
    build_enclave ${toolchain}
    enclave_path=${out}

    # Test mitigations
    test_load_value_injection ${enclave_path}
    test_stale_data_reads ${enclave_path}
    test_stale_data_reads_from_apic ${enclave_path}

    # Remove toolchain (if freshly installed)
    remove_toolchain ${toolchain}
}

function verify_mitigation {
    vuln=$1
    toolchain=$2

    build_enclave ${toolchain}
    enclave_path=${out}
    vers=`rustc +${toolchain} -V`
    ${vuln} ${enclave_path} "${toolchain} ($vers)"
}

function list_mitigations {
    echo "List mitigations"
    echo "Installing toolchains"
    install_toolchain nightly-2020-06-08
    install_toolchain nightly-2020-06-09
    install_toolchain nightly-2022-06-25
    install_toolchain nightly-2022-06-26
    install_toolchain nightly-2022-08-20
    install_toolchain nightly-2022-08-21

    echo "[ Load Value Injection ]"
    verify_mitigation test_load_value_injection nightly-2020-06-08
    verify_mitigation test_load_value_injection nightly-2020-06-09
    echo ""

    echo "[ MMIO Stale Data Reads ]"
    verify_mitigation test_stale_data_reads nightly-2022-06-25
    verify_mitigation test_stale_data_reads nightly-2022-06-26
    echo ""

    echo "[ Stale Data Reads for xAPIC ]"
    verify_mitigation test_stale_data_reads_from_apic nightly-2022-08-20
    verify_mitigation test_stale_data_reads_from_apic nightly-2022-08-21
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
