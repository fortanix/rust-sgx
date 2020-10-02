use crate::callback::*;
use crate::hacks::Usercall;
use crate::{AsyncUsercallProvider, CancelHandle};
use fortanix_sgx_abi::Fd;
use std::io;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;
use std::os::fortanix_sgx::usercalls::raw::UsercallNrs;

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
        self.send_usercall(u, callback.map(|cb| Callback::Read(cb)))
    }

    unsafe fn raw_write(
        &self,
        fd: Fd,
        buf: *const u8,
        len: usize,
        callback: Option<CbFn<io::Result<usize>>>,
    ) -> CancelHandle {
        let u = Usercall(UsercallNrs::write as _, fd as _, buf as _, len as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::Write(cb)))
    }

    unsafe fn raw_flush(&self, fd: Fd, callback: Option<CbFn<io::Result<()>>>) {
        let u = Usercall(UsercallNrs::flush as _, fd as _, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::Flush(cb)));
    }

    unsafe fn raw_close(&self, fd: Fd, callback: Option<CbFn<()>>) {
        let u = Usercall(UsercallNrs::close as _, fd as _, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::Close(cb)));
    }

    unsafe fn raw_bind_stream(
        &self,
        addr: *const u8,
        len: usize,
        local_addr: *mut ByteBuffer,
        callback: Option<CbFn<io::Result<Fd>>>,
    ) {
        let u = Usercall(UsercallNrs::bind_stream as _, addr as _, len as _, local_addr as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::BindStream(cb)));
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
        self.send_usercall(u, callback.map(|cb| Callback::AcceptStream(cb)))
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
        self.send_usercall(u, callback.map(|cb| Callback::ConnectStream(cb)))
    }

    unsafe fn raw_insecure_time(&self, callback: Option<CbFn<u64>>) {
        let u = Usercall(UsercallNrs::insecure_time as _, 0, 0, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::InsecureTime(cb)));
    }

    unsafe fn raw_alloc(&self, size: usize, alignment: usize, callback: Option<CbFn<io::Result<*mut u8>>>) {
        let u = Usercall(UsercallNrs::alloc as _, size as _, alignment as _, 0, 0);
        self.send_usercall(u, callback.map(|cb| Callback::Alloc(cb)));
    }

    unsafe fn raw_free(&self, ptr: *mut u8, size: usize, alignment: usize, callback: Option<CbFn<()>>) {
        let u = Usercall(UsercallNrs::free as _, ptr as _, size as _, alignment as _, 0);
        self.send_usercall(u, callback.map(|cb| Callback::Free(cb)));
    }
}
