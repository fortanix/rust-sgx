# Fortanix SGX ABI v0.3.2

This document describes the ABI of SGX enclaves built using `libenclave`.

## ABI version compatibility

| ABI version | Rust std version | enclave-runner version |
| -----------:| ----------------:| ----------------------:|
|       0.3.2 |        50f3d6e.. |            0.1.0~0.3.1 |
|       0.3.1 |        bd47d68.. |            0.1.0~0.3.1 |
|       0.3.0 |        15a2607.. |            0.1.0~0.3.1 |

| ABI version | libenclave version | enclave-interface version |
| -----------:| ------------------:| -------------------------:|
|       0.2.3 |        0.2.1-0.2.3 |               0.2.0-0.2.3 |
|       0.2.2 |        0.2.1-0.2.3 |               0.2.0-0.2.3 |
|       0.2.1 |        0.2.1-0.2.3 |               0.2.0-0.2.3 |
|       0.2.0 |        0.2.0-0.2.3 |                     0.2.0 |
|       0.1.3 |        0.1.0-0.1.3 |               0.1.0-0.1.1 |
|       0.1.0 |        0.1.0-0.1.3 |               0.1.0-0.1.1 |

### Changelog

#### Version 0.3.2

* *No semantic changes.*
* More changes to allow building as a crates.io dependency of `std`.

#### Version 0.3.1

* *No semantic changes.*
* Changes to allow building as a crates.io dependency of `std`.

#### Version 0.3.0

* Return values are now two registers wide instead of one.
* No longer distinguish between “panic exit” and “usercall exit”. Panic
  signalling is now done at the API level.
* Renamed “libenclave ABI” to “Fortanix SGX ABI”.
* TLS size and contents updated.

#### Version 0.2.3

* TLS size and contents updated.

#### Version 0.2.2

* TLS size updated. Debug TLS size is now the same as non-debug size.

#### Version 0.2.1

* AEX debug handler removed.

#### Version 0.2.0

* Usercall register saving semantics changed. The enclave no longer
  distinguishes between normal enters and usercall enters for purposes of
  saving user register state.

#### Version 0.1.3

* TLS size and contents updated.

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
- RSI
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

- `0`: Normal exit, any possible return value is in RDX:RSI. The TCS may be
  entered again later.
- Other: A “user call” is requested by the enclave. See below for register 
  usage. After servicing the user call request, execute EENTER again for the 
  same TCS. A normal exit following a usercall entry will return to the new
  entry point from where the usercall was returned.

### User call calling convention
  
Upon `EEXIT`, parameters are passed in:

- RDI
- RSI
- RDX
- R8
- R9

As discussed above under “exit value”, only non-zero values can be
passed in RDI. In addition, RDI values have special meaning as discussed below
under “Usercalls”.

Upon `EENTER`, a value is returned in:

- RSI
- RDX

The following registers will be saved by the caller (enclave):

- all registers (callee can use any register)

The following registers will be restored to the state they were in when the
enclave was last entered:

- RSP
- RBP
- R12
- R13
- R14
- R15

## Debug mode

This section describes the differences with the stated above when the enclave 
is compiled in debug mode.

### Enclave calling convention

Upon `EENTER`, a special parameter is passed in:

- R10

R10 should contain a pointer to a 1024-byte buffer in writable user memory. The 
enclave can write debugging messages to this buffer upon panic exit. The memory
location is only valid until the enclave performs `EEXIT`.
