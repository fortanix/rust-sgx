# report-test

This crate exposes a simple interface to get a local SGX attestation
(“report”). This is useful for testing remote attestation.

The enclave file itself is embedded in the library. The enclave uses the 
expiremental library support. At the time of writing, Rust `std` does not have
the ability to compile enclave libraries. Therefore, the enclave is written in
assembly.
