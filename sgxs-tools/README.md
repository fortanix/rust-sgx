# SGXS utilites

Compiles with Rust nightly.

## pe2sgxs

`pe2sgxs` converts enclaves in Intel's PE format to SGXS format, optionally
extracting the signature. You can then use the SGXS file with the other SGXS
utilities.

## sgx-debug-read

`sgx-debug-read` tries to reads memory in the EPC. This will only succeed for
regular and TCS pages that are part of debug enclaves. The contents of the
memory (or zeroes for inaccessible memory) will be output to stdout. Errors
will be printed to stderr.

## sgxs-build

`sgxs-build` generates an SGXS by concatenating raw binary files specified on
the command line. For example, to generate the simplest valid enclave possible:

```
$ as -k
mov %rcx,%rbx
mov $0x4,%eax
enclu
^D
$ objcopy -O binary -j .text a.out
$ sgxs-build rx=a.out tcs=nssa:1 > a.sgxs
$ sgxs-info info a.sgxs
   0- fff Reg  r-x  (data) meas=all
1000-1fff Tcs  ---  (data) meas=all
2000-2fff Reg  rw- (empty) meas=all
3000-3fff (unmapped)
```

Input files will be page-aligned.

## sgxs-info

`sgxs-info` parses SGXS files for further analysis. It currently supports the
following commands:

### list-all

The most verbose listing format, which lists all the individual commands
contained the input file, including their parameters. For EEXTEND commands,
data is as either `(empty)` if the data is all zeroes, `[byte]*` if the data is
all the same value `byte`, or `(data)` in any other case.

This is the only command that can read non-canonical SGXS files.

### list-pages

This listing format lists all commands, except EEXTEND commands. The EEXTEND
information is consolidated in the preceding EADD command. The data is
displayed in the same format as in the `list-all` command. The `measured` field
indicates which part of the page are being measured by an EEXTEND command:
`all`, `partial` or `none`.

### info

This command gives a summarized overview of all the different sections in
memory. The entire memory indicated by the enclave size is described.
Consecutive pages that have the same type, flags, data and measurement fields
are consolidated into a single line. Unmapped pages are indicated as such.

### dump-mem

This command dumps the memory of the enclave as it would be seen before
executing an EENTER instruction. Unmapped pages in between sections are filled
with zeroes. Unmapped pages at the end are truncated.

## sgxs-load

`sgxs-load` loads an SGXS file into the EPC. Currently, only the linux
ioctl driver is supported. You must also provide a signature and initialization
token.

## sgxs-sign

`sgxs-sign` generates a SIGSTRUCT given an SGX stream and user-specified
parameters. You can generate a fresh private key using the `openssl genrsa`
command like so:

```
openssl genrsa -3 3072 > private.pem
```
