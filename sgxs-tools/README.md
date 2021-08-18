# SGXS utilities

Compiles with Rust nightly.

## pe2sgxs

`pe2sgxs` converts enclaves in Intel's PE format to SGXS format, optionally
extracting the signature. You can then use the SGXS file with the other SGXS
utilities.

## sgx-debug-read

`sgx-debug-read` tries to read memory in the EPC. This will only succeed for
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
$ sgxs-info summary a.sgxs
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
contained in the input file, including their parameters. For EEXTEND commands,
data is either `(empty)` if the data is all zeroes, `[byte]*` if the data is
all the same value `byte`, or `(data)` in any other case.

This is the only command that can read non-canonical SGXS files.

### list-pages

This listing format lists all commands, except EEXTEND commands. The EEXTEND
information is consolidated in the preceding EADD command. The data is
displayed in the same format as in the `list-all` command. The `measured` field
indicates which part of the page are being measured by an EEXTEND command:
`all`, `partial` or `none`.

### summary

This command gives a summarized overview of all the different sections in
memory. The entire memory indicated by the enclave size is described.
Consecutive pages that have the same type, flags, data and measurement fields
are consolidated into a single line. Unmapped pages are indicated as such.
Characteristics of TCS pages are displayed.

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
parameters. It also supports a multi-step signing process, which is suggested to
keep the enclave signing key protected.

### Subcommands

#### sign

This is the one step signing process. It is also the default command. If the
`sgxs-sign` tool is used without a specified subcommand, this is the command
that is executed as to maintain backward compatibility with previous versions of
the `sgxs-sign` tool.

#### gendata

This is the first step in the multi-step signing process. It outputs the hash of
the sigstruct that must be signed by the the enclave signing key.

#### catsig

This is the final step in the multi-step signing process. It takes the
signature, public key, and the enclave parameters used in `gendata` to generate
a SIGSTRUCT. If the same options are _not_ used in both `gendata` and `catsig`,
`catsig` will fail to create a valid SIGSTRUCT.

#### verify

This command takes a public key of an enclave signer and a previously created
SIGSTRUCT and validates that the signature matches the public key. This _does
not_ validate an enclave hash to be correct. This simply ensures correctness in
the SIGSTRUCT itself.

### Usage

#### Generating a key

You can generate a fresh private key using the `openssl genrsa` command like so:

```
openssl genrsa -3 3072 > private.pem
```

#### Multi-step Signing Example

Multi-step signing allows enclave signing keys to be kept offline, preferrably
in some HSM. The following example uses `openssl` and a locally generated key as
an example, however, it is suggested that the key be stored in a more secure
location than in plaintext on disk.

##### Generate a key

Like above, we will generate a valid key for enclave signing. This must be a
3072-bit RSA key with a public exponent of 3. Do this like so:

```bash
openssl genrsa -3 3072 > private.pem
```

We will also need the public key in a later step so let's also generate this
now.

```bash
openssl rsa -in private.pem -pubout > public.pem
```

##### Generate signing data for your enclave

Generating signing data is done with the `gendata` subcommand, like so:

```bash
sgxs-sign gendata [options] [enclave_input] [sigstruct_hash_output]
```

_See `sgxs-sign gendata --help` for details on available options_

For purposes of this example, let's assume your enclave is named `foo.sgxs`. You
would generate data to sign like so:

```bash
sgxs-sign gendata foo.sgxs foo.sigstruct.sha256.bin
```

The output file `foo.sigstruct.sha256.bin` contains the sha256 hash of the
SIGSTRUCT fields to be signed.

##### Sign the SIGSTRUCT hash

To sign the SIGSTRUCT you must create a signature using the `RSASSA-PKCS1-v1_5`
scheme. The following command will do so with `openssl`. If you're using an HSM,
your device may have a different process for generating a signature of this
type.

```bash
openssl pkeyutl -sign \
      -in foo.sigstruct.sha256.bin \
      -inkey private.pem \
      -out foo.sigstruct.sha256.sig \
      -pkeyopt digest:sha256
```

##### Create the SIGSTRUCT with catsig

With the signature in `foo.sigstruct.sha256.sig` we can now generate a valid
SIGSTRUCT.

```bash
sgxs-sign catsig \
      --signature foo.sigstruct.sha256.sig \
      --public-key public.pem \
      foo.sgxs \
      foo.sig
```

If there are no errors, `foo.sig` will contain a valid SIGSTRUCT that was signed
by `private.pem`.
