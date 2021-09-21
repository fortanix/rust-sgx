#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/..)

function cargo_test {
    name=$1
    pushd ${repo_root}/FortanixVME/tests/$name
    out=$(mktemp)
    err=$(mktemp)

    if [ -f ./test_interaction.sh ]; then
        ./test_interaction.sh &
	test_interaction=$!
    fi

    VME_TARGET="${TOOLCHAIN_DIR}/rust/rustup/toolchains/nightly-2021-09-08-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-fortanixvme/x86_64-unknown-linux-fortanixvme.json"
    RUSTFLAGS="-Clink-self-contained=yes" \
      cargo build --release --target ${VME_TARGET} -Zbuild-std
    RUSTFLAGS="-Clink-self-contained=yes" \
      cargo run --release --target ${VME_TARGET} -Zbuild-std -- --nocapture > ${out} 2> ${err}

    if [ -f ./test_interaction.sh ]; then
        kill ${test_interaction}
    fi

    out=$(cat ${out} | grep -v "#")
    expected=$(cat ./out.expected)
    if [ "${out}" == "${expected}" ]; then
        echo "Ok"
    else
        echo "Test ${name} failed"
	exit -1
    fi

    cat ${out}
    cat ${err}
    popd
}

