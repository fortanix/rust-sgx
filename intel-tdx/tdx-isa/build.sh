#!/bin/bash -ex
intel_tdx=$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../")
SGX_SDK=${intel_tdx}/tdx-resources cargo build --features "tdx_module"
