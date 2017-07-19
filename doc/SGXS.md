# SGX stream format

The SGX stream (SGXS) format is the most basic description of an enclave, and
when combined with a signature and initialization token file contains all the
information needed by an Operating System to load the enclave.

The format consists entirely of all data that would be hashed to produce the
enclave measurement MRENCLAVE. As such, hashing an SGXS file with SHA-256 will
produce MRENCLAVE.

The format consists of records containing a 64-byte header (measurement blob)
and optionally some data. The header begins with an 8-byte tag and contains 56
bytes of header data. The three different tags are ECREATE, EADD and EEXTEND.
ECREATE and EADD blobs are not followed by any data. An EEXTEND blobs is
followed by exactly 256 bytes of data. For information on the headers and the
data, please refer to the Intel SGX Programming Reference.

## Canonicality

Most valid SGX streams are canonical. An SGXS stream is canonical if and only
if:

- the first measurement blob is an ECREATE blob, and no other blobs are an
  ECREATE blob,
- the offset of every EADD blob does not have the lower 12 bits set,
- the offset of every EADD blob is higher than that of any previous EADD blob,
- the offset of every EEXTEND blob does not have the lower 12 bits set,
- the upper 52 bits of offsets of all EEXTEND blobs are equal to those of the
  preceding EADD blob, and
- the lower 12 bits of offsets of all consecutive EEXTEND blobs are unique.

In other words, the stream begins with an ECREATE blob, all following blobs are
in logical order, and no memory address is specified more than once.

If you find that a particular SGX loader produces non-canonical SGX streams,
please contact the author with as much information about the loader and the
enclave as you can provide.
