use std::{alloc::{self, GlobalAlloc}, cell::Cell, ptr};

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
        let layout = alloc::Layout::from_size_align(sn_alloc_size, sn_alloc_align).unwrap();
        // TODO: bootstrap the thread-local allocator allocation a different way
        let allocator = alloc::alloc(layout) as *mut Alloc;
        sn_thread_init(allocator);
        THREAD_ALLOC.set(allocator);

        let r = f();

        THREAD_ALLOC.set(ptr::null_mut());
        sn_thread_cleanup(allocator);
        alloc::dealloc(allocator as _, layout);

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

        sn_global_init(heap.start as _, heap.end as _);
    }

    type AllocTestType = [u64; 20];

    let barrier = std::sync::Barrier::new(2);

    std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let barrier = &barrier;
        s.spawn(move || {
            unsafe {
                with_thread_allocator(|| {
                    let p1 = System.alloc(alloc::Layout::new::<AllocTestType>());
                    barrier.wait();
                    let p2 = System.alloc(alloc::Layout::new::<AllocTestType>());
                    tx.send((p1 as usize, p2 as usize)).unwrap();
                })
            };
        });

        let (p1, p2) = unsafe {
            with_thread_allocator(|| {
                let p1 = System.alloc(alloc::Layout::new::<AllocTestType>());
                barrier.wait();
                let p2 = System.alloc(alloc::Layout::new::<AllocTestType>());
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
