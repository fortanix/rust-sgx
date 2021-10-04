#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/../../)
cd ${repo_root}/FortanixVME

source ci-common.sh

cargo +${toolchain_version} build
