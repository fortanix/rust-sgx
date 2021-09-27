#!/bin/bash -ex
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))
cd ${repo_root}
docker build .
