# Fortanix SGX ELF specification

ELF is only an intermediate stage for the Fortanix SGX toolchain. Compatibility
is maintained at the source code and SGXS ABI level (see
[FORTANIX-SGX-ABI.md](FORTANIX-SGX-ABI.md)).

Nonetheless, this document describes the intermediate ELF format. This is for
reference purposes only, third parties should *not* rely on this format.

## ELF compatibility level

The compatibility level is contained in an ELF note section named
`.note.x86_64-fortanix-unknown-sgx`, note type `NT_VERSION` with name
`toolchain-version`. The contents of the note is a 32-bit little-endian number.

| toolchain-version | fortanix-sgx-tools version | Rust std version |
| -----------------:| --------------------------:|-----------------:|
|             1     |                0.4.0       |              TBD |
|             0     |          0.1.0~0.4.0       |        33e6df4.. |

### Changelog

#### Version 1

* Updated libunwind integration for new libunwind version

## Thread settings

This section describes the requirements on the SGX thread control structure 
(TCS), thread local storage (TLS) and thread stacks.

### TCS

- `NSSA` should be set to 1.
- `OGSBASGX` should point to a thread-specific memory region (e.g. TLS) of at 
  least 112 bytes.

### TLS

The memory region pointed to by `OGSBASGX` should be initialized as follows:

- Offset `0x0`: Top-of-Stack offset from image base.
- Offset `0x8`: `1` if this is an executable and this is a secondary TCS, `0`
  otherwise.
- Offsets `0x10`, `0x18`, `0x20`: `0`
- Offset `0x28`: The offset to the TCS structure from the image base.
- Offset `0x30`: The offset to the next TCSLS page (part of a circular linked
    list) from the image base.
- Other offsets: uninitialized.

## Globals

This section describes the requirements for various global constants in the SGX
binary.

- `HEAP_BASE`. Size 8 bytes. The base address (relative to enclave start) of
  the heap area, little-endian.
- `HEAP_SIZE`. Size 8 bytes. The heap size in bytes, little-endian.
- `ENCLAVE_SIZE`. Size 8 bytes. The enclave size in bytes, little-endian.
- `CFGDATA_BASE`. Size 8 bytes. The base address (relative to enclave start) of
  the enclave configuration area, little-endian.
- `RELA`. Size 8 bytes. Value of the RELA entry in the dynamic table.
- `RELACOUNT`. Size 8 bytes. Value of the RELACOUNT entry in the dynamic table.
- `DEBUG`. Size 1 byte. Non-zero if debugging is enabled, zero otherwise.
- `TEXT_BASE`. Size 8 bytes. The base address (relative to enclave start) of
   the enclave text section.
- `TEXT_SIZE`. Size 8 bytes. The size in bytes of the enclave text section.
- `EH_FRM_HDR_OFFSET`. Size 8 bytes. The base address (relative to enclave
  start) of the ELF section named '.eh_frame_hdr'.
- `EH_FRM_HDR_LEN`. Size 8 bytes. The size in bytes of the ELF section named
  '.eh_frame_hdr'.
- `EH_FRM_OFFSET`. Size 8 bytes. The base address (relative to enclave start)
  of the ELF section named '.eh_frame'.
- `EH_FRM_LEN`. Size 8 bytes. The size in bytes of the ELF section named
  '.eh_frame'.
