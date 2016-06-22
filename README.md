# sgx-utils

This repository is intended as an umbrella for various SGX utilities. See
individual directories and files for copyright information.

## doc

Documentation on various SGX file formats and ABIs.

## isgx

This is Intel's Linux SGX driver patchset assembled for an [external 
build](https://www.kernel.org/doc/Documentation/kbuild/modules.txt).

## linux-driver

Bare-bones SGX EPC driver. Exposes ENCLS pretty much directly to userspace. 
Included here for posterity. Don't use this. Use the isgx driver above.

## libenclave / libenclave-tools / enclave-interface

Rust library and runtime for SGX secure enclaves together with userland build 
tools and runtime support. Check out the [Quick start guide](doc/GUIDE.md).

## sgxs / sgxs-tools

Rust library and utilities for working with the SGX stream format.
