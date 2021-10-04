#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/../../../)
cd ${repo_root}/FortanixVME

source ci-common.sh
compile

elf=${repo_root}/FortanixVME/target/x86_64-unknown-linux-fortanixvme/release/incoming_connection
eif=$(mktemp /tmp/$name.eif.XXXXX)
elf2eif ${elf} ${eif}
eif_runner ${eif} ${out} ${err}
