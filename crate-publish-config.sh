#!/usr/bin/bash
#
# crate-publish-config.sh
#
# Usage:
#   source ./crate-publish-config.sh <crate_name>
#
# Sets environment variables and default toolchain for publishing/building a crate, based on crate name.
# Exports:
#   CARGO_BUILD_TARGET    - Target triple for build (e.g., x86_64-unknown-linux-gnu).
#                           This will affects cargo default build targets.
#
# Requirements:
#   - bash
#   - rustup
#
# Example:
#   source ./crate-publish-config.sh my-crate
#   echo $CARGO_BUILD_TARGET
#   rustup show
#

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: source \$0 <crate_name>" >&2
  return 1 2>/dev/null || exit 1
fi

CRATE_NAME="$1"

# Check for required tools
for tool in "rustup"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: Required tool '$tool' not found in PATH." >&2
    return 1 2>/dev/null || exit 1
  fi
done

# Set defaults
CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"

case "$CRATE_NAME" in
  # Example: crate that needs target SGX
  "async-usercalls")
    CARGO_BUILD_TARGET="x86_64-fortanix-unknown-sgx"
    rustup default nightly
    rustup target add $CARGO_BUILD_TARGET
    ;;
  *)
    ;;
  # Add more crate-specific configs here
esac

export CARGO_BUILD_TARGET
