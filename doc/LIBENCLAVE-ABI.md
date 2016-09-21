# libenclave ABI v0.1.0

This document describes the ABI of SGX enclaves built using `libenclave`.

## ABI version compatibility

| ABI version | libenclave version | enclave-interface version |
| -----------:| ------------------:| -------------------------:|
|       0.1.0 |        0.1.0-0.1.3 |               0.1.0-0.1.1 |

## Thread settings

This section describes the requirements on the SGX thread control structure 
(TCS), thread local storage (TLS) and thread stacks.

### TCS

- `NSSA` should be set to 1.
- `OGSBASGX` should point to a thread-specific memory region (e.g. TLS) of at 
  least 72 bytes.

### TLS

The memory region pointed to by `OGSBASGX` should be initialized as follows:

- Offset `0x0`: Top-of-Stack offset from image base.
- Offset `0x8`: `0`
- Other offsets: uninitialized.

## Enclave calling convention

Upon `EENTER`, besides the standard SGX control registers, parameters are 
passed in:

- RDI
- RSI
- RDX
- R8
- R9

Upon `EEXIT`, a value is returned in:

- RDI
- RDX

See below for the meaning of the values in these registers.

The following registers should be saved by the caller:

- ENCLU registers (RAX, RBX, RCX)
- R10
- R11

The following registers will be saved by the callee (enclave):

- RSP
- RBP
- R12
- R13
- R14
- R15

Flags are affected as follows:

- CF, PF, AF, ZF, SF, OF, DF are cleared

### Exit value

Upon `EEXIT`, RDI will have one of the following values:

- `0`: Normal exit, any possible return value is in RDX.
- Negative: The enclave encountered an abort condition. If the enclave is 
  entered again, it will immediately exit again with a negative value in RDI.
- Positive: A “user call” is requested by the enclave. See below for register 
  usage. After servicing the user call request, execute EENTER again for the 
  same TCS. A later normal exit will return to the point indicated by the 
  original call and will restore the register state as it was before the 
  original call as described above.

### User call calling convention
  
Upon `EEXIT`, parameters are passed in:

- RDI
- RSI
- RDX
- R8
- R9

See above under “exit value” which values can be passed in RDI. Upon `EENTER`, a value is returned in:

- RDX

The following registers will be saved by the caller (enclave):

- all registers (callee can use any register)

The following registers will be restored to the state they were in when the enclave was first entered:

- RSP
- RBP
- R12
- R13
- R14
- R15

## Debug mode

This section describes the differences with the stated above when the enclave 
is compiled in debug mode.

### TCS

- `NSSA` should be set to 2.

### Enclave calling convention

Upon `EENTER`, a special parameter is passed in:

- R10

R10 should contain a pointer to a 1024-byte buffer in writable user memory. The 
enclave can write debugging messages to this buffer upon panic exit.

### Asynchronous Enclave Exit (AEX)

When an enclave thread experiences an AEX event, that enclave thread can be 
entered again to call this function:

```rust
unsafe extern "C" fn debug_copy(dst: *mut u8, src: *const u8) {
	::core::ptr::copy_nonoverlapping(src,dst,0x1000);
}
```

Use the standard System V calling convention, except ENCLU registers (RAX, RBX, 
RCX) are also clobbered.
