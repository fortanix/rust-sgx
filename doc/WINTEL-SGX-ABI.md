# Wintel-SGX ABI

This document aims to describe the ABI for Intel-compatible Windows SGX
enclaves, such as those found in various "Software Guard Extensions" drivers.

## PE format

The enclaves are distributed in the Windows-standard PE format. 32-bit enclaves
are in the PE32 format, whereas 64-bit enclaves are in the PE32+ format. A
special section named `sgxmeta` contains loader information and the
`SIGSTRUCT`.

## Loader

The PE header is modified as follows and then loaded into the enclave at offset
0 with permissions set to R. The Checksum field of the optional header is set
to 0. The Certificate Table pointer and length are set to 0.

Then, most sections in the PE image are added to the enclave following the
normal memory loading procedure. These pages are measured in their entirety,
even when the file data for a section does not file a page. Protection flags
are mostly set according to the section characteristics, except all pages
containing relocations are also mapped W. Gaps between sections are also gaps
in the enclave address space. None of the sections, such as relocations, are
interpreted. The sections named `.tls` and `sgxmeta` have a special loading
procedure, see below.

Following the last PE page, the heap and thread-specific pages are allocated.
The `sgxmeta` section has information on how to do that. Immediately following
the last page in the enclave, enough R+W pages are added for the heap size
indicated in the `sgxmeta` section. These pages are not measured.

The next 16 pages (64KiB) in the address range are skipped, as a heap guard
area. Then, per thread--the number of which is specified in the `sgxmeta`
section--the following pages are added:

- A TCS page, measured. The contents of the TCS are described below.
- Enough empty R+W pages to fit the `.tls` section, measured. (TLS area)
- 16 pages are skipped (TLS guard area)
- TCS.NSSA*SSAFRAMESIZE empty R+W pages, measured. (SSA area)
- 16 pages are skipped (stack guard area)
- Enough R+W pages for the stack size indicated in the `sgxmeta` section. These
  pages are filled with 0xcc and measured. (stack area)

The TCS of a following thread immediately follows the last stack page of a
preceding thread.

### `sgxmeta` section

The `sgxmeta` section informs the loader how to load parts of the enclave that
are not parts of the PE image, such as the stack and the heap.

This section consists of a header followed by the `SIGSTRUCT`. Fields named
`unknown` are filled with the indicated data, the meaning of which is unknown
at this time.

```rust
#[repr(packed)]
struct Sgxmeta {
	// next 2 fields: presumably a header signature
	unknown0x635d0e4c: u32,
	unknown0x86a80294: u32,
	unknown0x00000001_1: u32,
	unknown0x00000001_2: u32,
	// the size of this structure
	struct_size: u32,
	// the number of threads to allocate
	threads: u32,
	// Field 8 in TLS section, see below
	tls_field_8: u32,
	tcs_nssa: u32,
	unknown0x00000001_3: u32,
	stack_size: u32,
	heap_size: u32,
	unknown0x00000a48: u32,
	unknown0x00000000: u32,
	requested_attributes: u64,
	// The XFRM attributes that should be enabled, if supported by the platform.
	requested_attributes_xfrm: u64,
	sigstruct: Sigstruct,
}
```

It's certainly possible that one of the currently unknown fields with `1` are
the SSA frame size. The SSA frame size is `1` for all currently known
platforms.

The sgxmeta section itself is not loaded into the enclave. Its part of the
address space is left unmapped.

### `.tls` section

The first few tens of bytes in the `.tls` section are overwritten by the
loader. The structure is different for 32-bit and 64-bit enclaves, but the
fields are the same. In the following structures, fields named `unchanged` mean
that the data is copied directly from the `.tls` section in the image file, as
is all data beyond the size of this structure. Fields named `unknown` are
filled with the indicated data, the meaning of which is unknown at this time.

```rust
#[repr(packed)]
struct Tls64 {
    unchanged1: u64,
    // Top-of-stack offset from TCS base
    tos_tcs_offset1: u64,
    // Top-of-stack offset from TCS base
    tos_tcs_offset2: u64,
    // Bottom-of-stack offset from TCS base
    bos_tcs_offset: u64,
    // Save state area (SSA) offset from TCS base
    ssa_tcs_offset: u64,
    // GPRSGX offset in the first SSA from TCS base
    gprsgx_tcs_offset: u64,
    // SSA size?
    unknown0x0000000000001000: u64,
    sgxmeta_field_7: u8,
    unchanged2: [u8;7],
    // Heap offset from enclave base
    heap_base_offset: u64,
    enclave_size: u64,
    unchanged3: u64,
    unknown0x0000000000001030: u64,
    unknown0x00000001: u32,
    heap_size: u32,
}

#[repr(packed)]
struct Tls32 {
    unknown0xffffffff: u32,
    // Top-of-stack offset from TCS base
    tos_tcs_offset1: u32,
    // Top-of-stack offset from TCS base
    tos_tcs_offset2: u32,
    // Bottom-of-stack offset from TCS base
    bos_tcs_offset: u32,
    // Save state area (SSA) offset from TCS base
    ssa_tcs_offset: u32,
    // GPRSGX offset in the first SSA from TCS base
    gprsgx_tcs_offset: u32,
    // SSA size?
    unknown0x00001000: u32,
    sgxmeta_field_7: u8,
    unchanged2: [u8;3],
    // Heap offset from enclave base
    heap_base_offset: u32,
    enclave_size: u32,
    unchanged3: u32,
    unknown0x00001018: u32,
    unknown0x00000001: u32,
    unchanged4: u32,
    heap_size: u32,
}
```

### TCS

Each TCS is initialized as follows:

- **OSSA**: relative address of the beginning of the following SSA area
			mentioned above.
- **NSSA**: tcs_nssa as specified in the `sgxmeta` header (field 8).
- **OENTRY**: relative address of the `enclave_entry` symbol in the PE export
			  directory.
- **OFSBASGX**: relative address of the beginning of the following TLS area
				mentioned above.
- **OGSBASGX**: relative address of the beginning of the following TLS area
				mentioned above.
- **FSLIMIT**: `0xfff`
- **GSLIMIT**: `0xfff`

All other fields are 0. Note that the FS/GS limits are always 1 page,
regardless of the size of the TLS area. Accesses to the TLS use a pointer in
the beginning of the TLS area to find the address of that area without having
to use segment addressing.

## `enclave_entry`

The entrypoint for each thread of the enclave is pointed to by the
`enclave_entry` symbol in the PE export directory. The entry has two input
parameters. A “call number” is passed in `%edi`. A call-specific parameter is
passed in `%rsi`. Upon return `%eax`, `%rbx`, `%rcx` are set according to
`ENCLU[EEXIT]`, `%rsp` and `%rbp` are preserved from entry, `%rdi` and `%rsi`
contain the return value, and the other 9 registers are cleared. A return value
other than `%rdi==0xffffffffffffffff && %rsi==0` indicates an error.

It seems that negative call numbers are reserved for platform
standard calls, whereas positive (including 0) call numbers are used for
enclave-specific calls.

### Known calls

What follows is a list of known calls for the platform and some
enclave-specific calls. Parameter types are described at the end.

#### Platform standard

The following calls seem to exist in every enclave.

| Call number (`%edi`) | Description  | Parameter (`%rsi`) |
| --------------------:| ------------ | ------------------ |
|                   -1 | Module init? | `*const Cpuinfo`   |

#### Enclave specific: LE

The following known calls pertain to the Launch Enclave.

| Call number (`%edi`) | Description         | Parameter (`%rsi`)  |
| --------------------:| ------------------- | ------------------- |
|                    0 | Generate EINITTOKEN | `*mut TokenRequest` |

This information was obtained from `le.signed.dll` version 1.0.26876.1392
(SHA-256: `015e790fc27ff7df756d4dca9da03df5b292105967563539d3f80c667c499fa2`).

**Generate EINITTOKEN**: this call will generate an EINITTOKEN for the supplied 
parameters. It is not exactly known what the policy implemented by the Launch 
Enclave is, but it seems that any call with the `DEBUG` attribute will return 
successfully. This call on its own is not sufficient to get tokens for the 
other Intel-supplied enclaves.

### Parameter types

#### `Cpuinfo`

The Cpuinfo type is a bitset indicating the existence of various CPU features
from CPUID. The encoding is obtained from the function at address
`0x1800011a0...0x18000163f` in `sgx_urts.dll` version 1.0.26826.1391 (SHA-256:
`edfa9670679a2ea8b6df31630ea0b70232dff484f0637a03b888d29114c3e591`).

| Bit | Feature name | Condition
| ---:| ------------ | -------------------------------------------
|   0 | (always set) |
|   1 | fpu          | `cpuid(1).edx[0]`
|   2 | cmov         | `cpuid(1).edx[15]`
|   3 | mmx          | `cpuid(1).edx[23]`
|   4 | fxsr         | `cpuid(1).edx[24]`
|   5 | sse          | `cpuid(1).edx[25] && fxsr`
|   6 | sse2         | `cpuid(1).edx[26] && fxsr`
|   7 | sse3         | `cpuid(1).ecx[0] && fxsr`
|   8 | ssse3        | `cpuid(1).ecx[9] && fxsr`
|   9 | sse4.1       | `cpuid(1).ecx[19] && fxsr`
|  10 | sse4.2       | `cpuid(1).ecx[20] && fxsr`
|  11 | popcnt       | `cpuid(1).ecx[23] && fxsr`
|  12 | movbe        | `cpuid(1).ecx[22] && fxsr`
|  13 | pclmulqdq    | `cpuid(1).ecx[1] && fxsr`
|  14 | aes          | `cpuid(1).ecx[25] && fxsr`
|     | osxsave      | `cpuid(1).ecx[27]`
|  15 | f16c         | `cpuid(1).ecx[29] && osxsave`
|  16 | avx          | `cpuid(1).ecx[28] && osxsave`
|  17 | rdrnd        | `cpuid(1).ecx[30]`
|  18 | fma3         | `cpuid(1).ecx[12] && osxsave`
|  19 | bmi1+bmi2    | `cpuid(7).ebx[3] && cpuid(7).ebx[8]`
|  20 | lzcnt        | `cpuid(0x80000001).ecx[5]`
|  21 | hle          | `cpuid(7).ebx[4]`
|  22 | rtm          | `cpuid(7).ebx[11]`
|  23 | avx2         | `cpuid(7).ebx[5] && osxsave`
|  24 | (reserved?)  |
|  25 | prefetchw    | `cpuid(0x80000001).ecx[8]`
|  26 | rdseed       | `cpuid(7).ebx[18]`
|  27 | adx          | `cpuid(7).ebx[19]`
|     | model        | `cpuid(1).eax[19:16]:cpuid(1).eax[7:4]`
|  28 | atom         | `model==0x1c || model==0x26 || model==0x27`

All other bits are clear.

[According to
Intel](https://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers),
the model numbers for bit 28 refer to various Atom processors: `0x1c` is
Pineview, Silverthorne, Diamondville, Stellarton, `0x26` is Lincroft, Tunnel
Creek, `0x27` is Penwell.

Note that the Enclave can not rely on the information in this field because it
is passed in by the untrusted process.

#### `TokenRequest`

The input parameter for the “Generate EINITTOKEN” call of the Launch Enclave is
as follows:

```rust
#[repr(packed)]
struct TokenRequest {
	/// Unused
	unused: u64,
	/// Pointer to MRENCLAVE for the requested token
	mrenclave: *const [u8;32],
	/// Pointer to MRSIGNER for the requested token
	mrsigner: *const [u8;32],
	/// Pointer to attributes for the requested token
	attributes: *const Attributes,
	/// Pointer to caller-allocated buffer receiving the token
	einittoken: *mut Einittoken,
}
```
