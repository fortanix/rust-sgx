This is a subset of libc that can be used with Rust inside SGX. Functions are
added on an as-needed basis.

## errno

errno is not supported. Functions that have had errno functionality removed:

* strtod
* strtof
* strtoimax
* strtol
* strtold
* strtoll
* strtoul
* strtoull
* strtoumax
