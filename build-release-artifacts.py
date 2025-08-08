#!/usr/bin/env python3

import argparse
import shutil
import subprocess
import gzip
import json
from pathlib import Path


def run_command(cmd, append_to=None):
    """Run a shell command and optionally append output to a file."""
    print(f"Getting output of: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if append_to:
        print(f"Saving output to: {append_to}")
        with open(append_to, "a") as f:
            f.write(result.stdout)
            f.write(result.stderr)
    else:
        print(result.stdout)
        print(result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description="Build and package given package's binary targets.")
    parser.add_argument(
        "--target",
        required=True,
        help="Target triple for cargo build (e.g., x86_64-unknown-linux-gnu)",
    )
    parser.add_argument("--package", required=True, help="Package name for cargo build")
    args = parser.parse_args()

    # Get cargo metadata
    metadata_cmd = "cargo metadata --no-deps --format-version 1"
    print(f"Running: {metadata_cmd}")
    metadata_result = subprocess.run(
        metadata_cmd, shell=True, capture_output=True, text=True
    )
    if metadata_result.returncode != 0:
        print("Error: Failed to get cargo metadata")
        print(metadata_result.stderr)
        exit(metadata_result.returncode)
    metadata = json.loads(metadata_result.stdout)

    # Find the package
    pkg = None
    for p in metadata["packages"]:
        if p["name"] == args.package:
            pkg = p
            break
    if not pkg:
        print(f"Error: Package '{args.package}' not found in cargo metadata.")
        exit(1)

    # Find bin targets
    bin_targets = []
    for target in pkg.get("targets", []):
        if "bin" in target.get("kind", []) and "bin" in target.get("crate_types", []):
            bin_targets.append(target)

    if not bin_targets:
        print(
            f"No binary targets found for package '{args.package}'. Nothing to build."
        )
        exit(0)

    dist_dir = Path("dist")
    dist_dir.mkdir(exist_ok=True)

    # Build the package (will build all binaries for the package)
    build_cmd = f'cargo build --locked --release --target "{args.target}" --package "{args.package}"'
    print(f"Running: {build_cmd}")
    result = subprocess.run(build_cmd, shell=True)
    if result.returncode != 0:
        exit(result.returncode)

    for target in bin_targets:
        binary_name = target["name"]
        binary_path = Path("target") / args.target / "release" / binary_name

        if not binary_path.exists():
            print(f"Warning: Built binary not found at {binary_path}, skipping.")
            continue

        print(f"Collecting build artifact: {binary_path}")
        # Move binary to dist
        dest_binary = dist_dir / binary_name
        shutil.move(str(binary_path), str(dest_binary))

        # Create .tgz archive to preserve permissions
        tgz_name = f"{binary_name}-{args.target}.tgz"
        tgz_path = dist_dir / tgz_name
        print(f"Creating .tgz archive for build artifact at: {tgz_path}")
        import tarfile
        with tarfile.open(tgz_path, "w:gz") as tar:
            tar.add(dest_binary, arcname=binary_name)

        # Remove the binary after archiving
        print(f"Removing build artifact: {dest_binary}")
        dest_binary.unlink()

    # Collect build info
    build_info_path = dist_dir / "build-info.txt"
    print(f"Generating: {build_info_path}")
    for tool in [
        "cargo --version --verbose",
        "rustc --version --verbose",
    ]:
        run_command(tool, append_to=build_info_path)


if __name__ == "__main__":
    main()
