#!/bin/bash -ex
this_dir=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")
cd ${this_dir}

docker build -t ppid_retrieval:$(cat version) -f ./Dockerfile ../

set +x
echo "Build ready, you can run the tool"
echo ""
echo "  docker run --device /dev/sgx ppid_retrieval:$(cat version)"
echo ""
echo "Note: the SGX device on your host may differ"
