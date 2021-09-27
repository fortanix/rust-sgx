#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}

# Build tools
docker build -t fortanix_vme/compilation_tools:v0.1 .
containerid=$(docker create fortanix_vme/compilation_tools:v0.1)

# Output tools
rm -rf tools
mkdir -p tools/
docker cp ${containerid}:/tmp/fortanixvme/ tools/
