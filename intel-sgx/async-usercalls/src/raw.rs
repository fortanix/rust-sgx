use crate::callback::*;
use crate::{AsyncUsercallProvider, CancelHandle};
use fortanix_sgx_abi::Fd;
use std::io;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;
use std::os::fortanix_sgx::usercalls::raw::{Usercall, UsercallNrs};

pub trait RawApi {
    unsafe fn raw_read(
        &self,
        fd: Fd,
        buf: *mut u8,
        len: usize,
        callback: Option<CbFn<io::Result<usize>>>,
    ) -> CancelHandle;

    unsafe fn raw_write(
        &self,
        fd: Fd,
        buf: *const u8,
        len: usize,
        callback: Option<CbFn<io::Result<usize>>>,
    ) -> CancelHandle;

    unsafe fn raw_flush(&self, fd: Fd, callback: Option<CbFn<io::Result<()>>>);

    unsafe fn raw_close(&self, fd: Fd, callback: Option<CbFn<()>>);

    unsafe fn raw_bind_stream(
        &self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    );

    unsafe fn raw_accept_stream(
        &self,
        fd: Fd,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) -> CancelHandle;

    unsafe fn raw_connect_stream(
        &self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) -> CancelHandle;

    unsafe fn raw_insecure_time(&self, callback: Option<CbFn<u64>>);

    unsafe fn raw_alloc(&self, size: usize, alignment: usize, callback: Option<CbFn<io::Result<*mut u8>>>);

    unsafe fn raw_free(&self, ptr: *mut u8, size: usize, alignment: usize, callback: Option<CbFn<()>>);
}

impl RawApi for AsyncUsercallProvider {
    unsafe fn raw_read(
        &self,
        fd: Fd,
        buf: *mut u8,
        len: usize,
        callback: Option<CbFn<io::Result<usize>>>,
    ) -> CancelHandle {
        let u = Usercall(UsercallNrs::read as _, fd as _, buf as _, len as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::read(cb)))
    }

    unsafe fn raw_write(
        &self,
        fd: Fd,
        buf: *const u8,
        len: usize,
        callback: Option<CbFn<io::Result<usize>>>,
    ) -> CancelHandle {
        let u = Usercall(UsercallNrs::write as _, fd as _, buf as _, len as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::write(cb)))
    }

    unsafe fn raw_flush(&self, fd: Fd, callback: Option<CbFn<io::Result<()>>>) {
        let u = Usercall(UsercallNrs::flush as _, fd as _, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::flush(cb)));
    }

    unsafe fn raw_close(&self, fd: Fd, callback: Option<CbFn<()>>) {
        let u = Usercall(UsercallNrs::close as _, fd as _, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::close(cb)));
    }

    unsafe fn raw_bind_stream(
        &self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) {
        let u = Usercall(UsercallNrs::bind_stream as _, addr as _, len as _, local_addr as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::bind_stream(cb)));
    }

    unsafe fn raw_accept_stream(
        &self,
        fd: Fd,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) -> CancelHandle {
        let u = Usercall(
            UsercallNrs::accept_stream as _,
            fd as _,
            local_addr as _,
            peer_addr as _,
            0,
        );
        self.send_usercall(u, callback.map(|cb| Callback::accept_stream(cb)))
    }

    unsafe fn raw_connect_stream(
        &self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        peer_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) -> CancelHandle {
        let u = Usercall(
            UsercallNrs::connect_stream as _,
            addr as _,
            len as _,
            local_addr as _,
            peer_addr as _,
        );
        self.send_usercall(u, callback.map(|cb| Callback::connect_stream(cb)))
    }

    unsafe fn raw_insecure_time(&self, callback: Option<CbFn<u64>>) {
        let u = Usercall(UsercallNrs::insecure_time as _, 0, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::insecure_time(cb)));
    }

    unsafe fn raw_alloc(&self, size: usize, alignment: usize, callback: Option<CbFn<io::Result<*mut u8>>>) {
        let u = Usercall(UsercallNrs::alloc as _, size as _, alignment as _, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::alloc(cb)));
    }

    unsafe fn raw_free(&self, ptr: *mut u8, size: usize, alignment: usize, callback: Option<CbFn<()>>) {
        let u = Usercall(UsercallNrs::free as _, ptr as _, size as _, alignment as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::free(cb)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crossbeam_channel as mpmc;
    use std::io;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn get_time_async_raw() {
        fn run(tid: u32, provider: AutoPollingProvider) -> (u32, u32, Duration) {
            let pid = provider.provider_id();
            const N: usize = 500;
            let (tx, rx) = mpmc::bounded(N);
            for _ in 0..N {
                let tx = tx.clone();
                let cb = move |d| {
                    let system_time = UNIX_EPOCH + Duration::from_nanos(d);
                    tx.send(system_time).unwrap();
                };
                unsafe {
                    provider.raw_insecure_time(Some(cb.into()));
                }
            }
            let mut all = Vec::with_capacity(N);
            for _ in 0..N {
                all.push(rx.recv().unwrap());
            }

            assert_eq!(all.len(), N);
            // The results are returned in arbitrary order
            all.sort();
            let t0 = *all.first().unwrap();
            let tn = *all.last().unwrap();
            let total = tn.duration_since(t0).unwrap();
            (tid, pid, total / N as u32)
        }

        println!();
        const THREADS: usize = 4;
        let mut providers = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            providers.push(AutoPollingProvider::new());
        }
        let mut handles = Vec::with_capacity(THREADS);
        for (i, provider) in providers.into_iter().enumerate() {
            handles.push(thread::spawn(move || run(i as u32, provider)));
        }
        for h in handles {
            let res = h.join().unwrap();
            println!("[{}/{}] (Tn - T0) / N = {:?}", res.0, res.1, res.2);
        }
    }

    #[test]
    fn raw_alloc_free() {
        let provider = AutoPollingProvider::new();
        let ptr: Arc<AtomicPtr<u8>> = Arc::new(AtomicPtr::new(0 as _));
        let ptr2 = Arc::clone(&ptr);
        const SIZE: usize = 1024;
        const ALIGN: usize = 8;

        let (tx, rx) = mpmc::bounded(1);
        let cb_alloc = move |p: io::Result<*mut u8>| {
            let p = p.unwrap();
            ptr2.store(p, Ordering::Relaxed);
            tx.send(()).unwrap();
        };
        unsafe {
            provider.raw_alloc(SIZE, ALIGN, Some(cb_alloc.into()));
        }
        rx.recv().unwrap();
        let p = ptr.load(Ordering::Relaxed);
        assert!(!p.is_null());

        let (tx, rx) = mpmc::bounded(1);
        let cb_free = move |()| {
            tx.send(()).unwrap();
        };
        unsafe {
            provider.raw_free(p, SIZE, ALIGN, Some(cb_free.into()));
        }
        rx.recv().unwrap();
    }
}
