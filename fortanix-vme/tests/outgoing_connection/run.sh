#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/../../../)
cd ${repo_root}/fortanix-vme

source ci-common.sh
compile

eif=$(mktemp /tmp/$name.eif.XXXXX)
elf2eif ${elf} ${eif}
eif_runner ${eif} ${out} ${err}
