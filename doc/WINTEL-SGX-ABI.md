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

This section consists of a header followed by the `SIGSTRUCT`. A field named
`unknown` ìs filled with the indicated data, the meaning of which is unknown at
this time.

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
fields are the same. In the following structures, a field named `unchanged`
means that the data is copied directly from the `.tls` section in the image
file, as is all data beyond the size of this structure. A field named `unknown`
ìs filled with the indicated data, the meaning of which is unknown at this
time.

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
    // ERRCD offset in the first SSA from TCS base
    errcd_tcs_offset: u64,
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
    // ERRCD offset in the first SSA from TCS base
    errcd_tcs_offset: u32,
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
regardless of the size of the TLS area. Access to the TLS use a pointer in the
beginning of the TLS area to find the address of that area without having to
use segment addressing.
