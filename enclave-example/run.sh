#!/bin/sh
SELF="$(dirname "$0")"
sgxs-sign --key "$SELF/"trusted/target/debug/private.pem -d "$SELF/"trusted/target/debug/enclave_example.sgxs "$SELF/"trusted/target/debug/enclave_example.sig
#gdb --args
"$SELF/"untrusted/target/debug/enclave-runner "$SELF/"trusted/target/debug/enclave_example.sgxs "$SELF/"trusted/target/debug/enclave_example.sig "$SELF/"le.signed.sgxs "$SELF/"le.signed.sig
