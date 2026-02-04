// Fake VDSO with symbols only used for linking
.global __vdso_sgx_enter_enclave
.type __vdso_sgx_enter_enclave, function
.global __vdso_clock_gettime
.type __vdso_clock_gettime, function
__vdso_clock_gettime:
__vdso_sgx_enter_enclave:
ret
