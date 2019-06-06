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
- the offset of every EEXTEND blob does not have the lower 8 bits set,
- the page permissions bits of every EADD blob representing a TCS page are not set.
- the upper 52 bits of offsets of all EEXTEND blobs are equal to those of the
  preceding EADD blob, and
- the lower 12 bits of offsets of all consecutive EEXTEND blobs are unique.

In other words, the stream begins with an ECREATE blob, all following blobs are
in logical order (except EEXTEND blobs within a page maybe out of order), and
no memory address is specified more than once.

If you find that a particular SGX loader produces non-canonical SGX streams,
please contact the author with as much information about the loader and the
enclave as you can provide.

# Enhanced SGX stream format

The enhanced SGX stream (ESGXS) format is similar to the SGXS format but can
contain records that do not directly correspond to the enclave measurement.

## Additional records

The following extra records are specified:

### UNSIZED

An UNSIZED record may appear instead of an ECREATE record. It indicates that
the total enclave size is yet to be determined. The data following the UNSIZED
tag is the same as for an ECREATE record, with one exception. Bits 96 through
159, which in an ECREATE record contain the enclave size, instead contain a
memory offset. At this offset, the enclave size should be written as a 64-bit
little endian number when finalizing the size of the enclave.

### UNMEASRD

An UNMEASRD record may appear instead of an EEXTEND record. It represents data
that is loaded into memory but not measured. The data following the UNMEASRD
tag is the same as for an EEXTEND record.

## Measuring

An ESGXS stream beginning with an UNSIZED record cannot be measured. Once the
size is determined, the UNSIZED record must be replaced with an ECREATE record
and the size must be inserted into the enclave memory as described in the
UNSIZED record description.

An ESGXS stream containing UNMEASRD records can be measured. UNMEASRD records,
including the memory data, must be skipped over during the measuring.

## Canonicality

An ESGXS stream is canonical if and only if when replacing all occurences of
UNSIZED and UNMEASRD records with ECREATE and EEXTEND records, respectively,
the resulting SGXS stream is canonical.
