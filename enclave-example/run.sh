#!/bin/sh
SELF="$(dirname "$0")"
sgxs-sign --key "$SELF/"trusted/target/x86_64-unknown-none-gnu/debug/private.pem -d "$SELF/"trusted/target/x86_64-unknown-none-gnu/debug/enclave-example.sgxs "$SELF/"trusted/target/x86_64-unknown-none-gnu/debug/enclave-example.sig
#gdb --args
"$SELF/"untrusted/target/debug/enclave-runner "$SELF/"trusted/target/x86_64-unknown-none-gnu/debug/enclave-example.sgxs "$SELF/"trusted/target/x86_64-unknown-none-gnu/debug/enclave-example.sig "$SELF/"le.signed.sgxs "$SELF/"le.signed.sig
