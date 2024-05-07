// Copyright (c) Microsoft Corporation.
// Copyright (c) Open Enclave SDK contributors.
// Copyright (c) 2020 SchrodingerZhu
// Copyright (c) Fortanix, Inc.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE

#include <immintrin.h>
#include <string.h>

/***************************************************/
/*** Imported symbols needed by snmalloc SGX PAL ***/
/***************************************************/

// from entry.S
extern "C" size_t get_tcs_addr();

// from Rust std
extern "C" void __rust_print_err(const char *m, size_t s);
extern "C" [[noreturn]] void __rust_abort();

/*******************************************************/
/*** Standard C functions needed by snmalloc SGX PAL ***/
/*******************************************************/

// definition needs to match GNU header
extern "C" [[noreturn]] void abort() __THROW {
    __rust_abort();
}

// definition needs to match GNU header
extern "C" inline int * __attribute_const__ __errno_location (void) __THROW {
    static int errno;
    return &errno;
}

extern "C" {
    static size_t HEAP_BASE;
    static size_t HEAP_SIZE;
};

/***********************************/
/*** snmalloc SGX PAL definition ***/
/***********************************/

#define SNMALLOC_PROVIDE_OWN_CONFIG
#define SNMALLOC_SGX
#define SNMALLOC_USE_SMALL_CHUNKS
#define SNMALLOC_MEMORY_PROVIDER PALEdpSgx
#define OPEN_ENCLAVE
// needed for openenclave header:
#define OE_OK 0

#include "../snmalloc/src/snmalloc/pal/pal_noalloc.h"

namespace snmalloc {
void register_clean_up() {
    // TODO: not sure what this is supposed to do
    abort();
}

class EdpErrorHandler {
  public:
    static void print_stack_trace() {}

    [[noreturn]] static void error(const char *const str) {
        __rust_print_err(str, strlen(str));
        abort();
    }
    static constexpr size_t address_bits = Aal::address_bits;
    static constexpr size_t page_size = Aal::smallest_page_size;
};

using EdpBasePAL = PALNoAlloc<EdpErrorHandler>;

class PALEdpSgx : public EdpBasePAL {
   public:
    const static size_t RAND_NUM_GEN_MAX_RETRIES = 64;
    using ThreadIdentity = size_t;
    static constexpr uint64_t pal_features = EdpBasePAL::pal_features | Entropy;

    template <bool page_aligned = false>
    static void zero(void *p, size_t size) noexcept {
        memset(p, 0, size);
    }

    static inline uint64_t get_entropy64() {
        long long unsigned int retry_count = 0;
        long long unsigned int result = 0;
        while (_rdrand64_step(&result) != 1 && retry_count < RAND_NUM_GEN_MAX_RETRIES) {
            retry_count++;
        }
        return result;
    }

    static inline ThreadIdentity get_tid() noexcept {
        return (size_t)get_tcs_addr();
    }
};
} // namespace snmalloc

/**************************************/
/*** Instantiation of the allocator ***/
/**************************************/

#include "../snmalloc/src/snmalloc/backend/fixedglobalconfig.h"
#include "../snmalloc/src/snmalloc/snmalloc_core.h"

using namespace snmalloc;

using Globals = FixedRangeConfig<PALEdpSgx>;
using Alloc = LocalAllocator<Globals>;

/// Do global initialization for snmalloc. Should be called exactly once prior
/// to any other snmalloc function calls.
// TODO: this function shouldn't need the addresses passed in, these can be
// obtained from the HEAP_* symbols
extern "C" void sn_global_init() {
    Globals::init(nullptr, (void *)HEAP_BASE, HEAP_SIZE);
}

/// Construct a thread-local allocator object in place
extern "C" void sn_thread_init(Alloc* allocator) {
    new(allocator) Alloc();
    allocator->init();
}

/// Destruct a thread-local allocator object in place
extern "C" void sn_thread_cleanup(Alloc* allocator) {
    allocator->teardown();
    allocator->~Alloc();
}

extern "C" size_t sn_alloc_size = sizeof(Alloc);
extern "C" size_t sn_alloc_align = alignof(Alloc);

/// Return a pointer to a thread-local allocator object of size
/// `sn_alloc_size` and alignment `sn_alloc_align`.
extern "C" Alloc* __rust_get_thread_allocator();

/******************************************************/
/*** Rust-compatible shims for the global allocator ***/
/******************************************************/

extern "C" void *sn_rust_alloc(size_t alignment, size_t size) {
    return __rust_get_thread_allocator()->alloc(aligned_size(alignment, size));
}

extern "C" void *sn_rust_alloc_zeroed(size_t alignment, size_t size) {
    return __rust_get_thread_allocator()->alloc<YesZero>(
        aligned_size(alignment, size));
}

extern "C" void sn_rust_dealloc(void *ptr, size_t alignment, size_t size) {
    __rust_get_thread_allocator()->dealloc(ptr, aligned_size(alignment, size));
}

extern "C" void *sn_rust_realloc(void *ptr, size_t alignment, size_t old_size,
                                 size_t new_size) {
    size_t aligned_old_size = aligned_size(alignment, old_size),
           aligned_new_size = aligned_size(alignment, new_size);
    if (size_to_sizeclass_full(aligned_old_size).raw() ==
        size_to_sizeclass_full(aligned_new_size).raw())
        return ptr;
    Alloc* allocator = __rust_get_thread_allocator();
    void *p = allocator->alloc(aligned_new_size);
    if (p) {
        std::memcpy(p, ptr, old_size < new_size ? old_size : new_size);
        allocator->dealloc(ptr, aligned_old_size);
    }
    return p;
}
