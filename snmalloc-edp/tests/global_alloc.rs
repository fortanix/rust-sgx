use std::{alloc::{self, GlobalAlloc}, cell::Cell, ptr};
use std::ptr::null_mut;

use snmalloc_edp::*;

thread_local! {
    static THREAD_ALLOC: Cell<*mut Alloc> = const { Cell::new(ptr::null_mut()) };
}

#[no_mangle]
pub fn __rust_get_thread_allocator() -> *mut Alloc {
    THREAD_ALLOC.get()
}

struct System;

unsafe impl alloc::GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        sn_rust_alloc(layout.align(), layout.size())
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: alloc::Layout) -> *mut u8 {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        sn_rust_alloc_zeroed(layout.align(), layout.size())
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        sn_rust_dealloc(ptr, layout.align(), layout.size())
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: alloc::Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller must uphold the safety contract for `malloc`
        sn_rust_realloc(ptr, layout.align(), layout.size(), new_size)
    }
}

// SAFETY: this should only be called once per thread, and the global
// allocator shouldn't be used outside of this function
unsafe fn with_thread_allocator<F: FnOnce() -> R, R>(f: F) -> R {
    unsafe {
        let mut allocator = std::mem::MaybeUninit::<Alloc>::uninit();
        sn_thread_init(allocator.as_mut_ptr());
        THREAD_ALLOC.set(allocator.as_mut_ptr());

        let r = f();

        THREAD_ALLOC.set(null_mut());
        sn_thread_cleanup(allocator.as_mut_ptr());

        r
    }
}

#[test]
fn test() {
    unsafe {
        #[allow(dead_code)]
        #[derive(Copy, Clone)]
        #[repr(align(0x1000))]
        struct Page([u8; 0x1000]);

            // allocate a dummy heap
            let heap = (*Box::into_raw(vec![Page([0; 4096]); 100].into_boxed_slice())).as_mut_ptr_range();
            let heap_size = heap.end as usize - heap.start as usize;
            sn_global_init(heap.start as _, heap_size);
    }

    const TEST_ARRAY_SIZE :usize = 20;
    type AllocTestType = [u64; TEST_ARRAY_SIZE];

    let barrier = std::sync::Barrier::new(2);

    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let barrier = &barrier;
        s.spawn(move || {
            unsafe {
                // Initialize thread allocator and perform alloc/alloc_zeroed
                with_thread_allocator(|| {
                    let p1 = System.alloc(alloc::Layout::new::<AllocTestType>());
                    barrier.wait();
                    let p2 = System.alloc_zeroed(alloc::Layout::new::<AllocTestType>());

                    let p2_slice = std::slice::from_raw_parts_mut(p2, TEST_ARRAY_SIZE);
                    for i in 0..TEST_ARRAY_SIZE {
                        assert_eq!(p2_slice[i], 0);
                    }

                    tx.send((p1 as usize, p2 as usize)).unwrap();
                })
            };
        });

        let (p1, p2) = unsafe {
            with_thread_allocator(|| {
                let p1 = System.alloc(alloc::Layout::new::<AllocTestType>());
                barrier.wait();
                let p2 = System.alloc(alloc::Layout::new::<AllocTestType>());

                // Test realloc
                let p3 = System.realloc(p1, alloc::Layout::new::<AllocTestType>(), TEST_ARRAY_SIZE * 2);
                assert_ne!(p3, p2);

                (p1 as usize, p2 as usize)
            })
        };

        let (p3, p4) = rx.recv().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p1, p4);
        assert_ne!(p2, p3);
        assert_ne!(p2, p4);
        assert_ne!(p3, p4);

    })

}
