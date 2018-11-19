# enclave-runner

This is an interface library to work with SGX enclaves implementing the 
[Fortanix SGX ABI](../doc/FORTANIX-SGX-ABI.md). If you write an enclave using 
the `x86_64-fortanix-unknown-sgx` target, you will probably want to write a
userspace tool using this library.

Compiles with Rust nightly.
