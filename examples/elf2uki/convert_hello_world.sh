#!/bin/bash
set -euo pipefail

source_dir=$(dirname "${BASH_SOURCE[0]}")
app_dir="$source_dir/hello_world"

pushd "$app_dir"
#builds statically linked bin for `musl`
cargo -q build --release
popd

# build UKI and write it to `/dev/null`
cargo -q run -p elf2uki -- \
    --app "$app_dir/target/x86_64-unknown-linux-musl/release/hello_world" \
    --cmdline "console=ttyS0 earlyprintk=serial" \
    --output /dev/null
