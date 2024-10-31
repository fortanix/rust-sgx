use crate::batch_drop;
use crate::io_bufs::UserBuf;
use crate::raw::RawApi;
use crate::utils::MakeSend;
use crate::{AsyncUsercallProvider, CancelHandle};
use fortanix_sgx_abi::{Fd, InsecureTimeInfo};
use std::io;
use std::mem::{self, ManuallyDrop};
use std::net::{TcpListener, TcpStream};
use std::os::fortanix_sgx::io::{FromRawFd, TcpListenerMetadata, TcpStreamMetadata};
use std::os::fortanix_sgx::usercalls::alloc::{User, UserRef, UserSafe};
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl AsyncUsercallProvider {
    /// Sends an asynchronous `read` usercall. `callback` is called when a
    /// return value is received from userspace. `read_buf` is returned as an
    /// argument to `callback` along with the result of the `read` usercall.
    ///
    /// Returns a handle that can be used to cancel the usercall if desired.
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn read<F>(&self, fd: Fd, read_buf: User<[u8]>, callback: F) -> CancelHandle
        where
            F: FnOnce(io::Result<usize>, User<[u8]>) + Send + 'static,
    {
        let mut read_buf = ManuallyDrop::new(MakeSend::new(read_buf));
        let ptr = read_buf.as_mut_ptr();
        let len = read_buf.len();
        let cb = move |res: io::Result<usize>| {
            // Passing a `User<u8>` likely leads to the value being dropped implicitly,
            // which will cause a synchronous `free` usercall.
            // See: https://github.com/fortanix/rust-sgx/issues/531
            let read_buf = ManuallyDrop::into_inner(read_buf).into_inner();
            callback(res, read_buf);
        };
        unsafe { self.raw_read(fd, ptr, len, Some(cb.into())) }
    }

    /// Sends an asynchronous `write` usercall. `callback` is called when a
    /// return value is received from userspace. `write_buf` is returned as an
    /// argument to `callback` along with the result of the `write` usercall.
    ///
    /// Returns a handle that can be used to cancel the usercall if desired.
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn write<F>(&self, fd: Fd, write_buf: UserBuf, callback: F) -> CancelHandle
        where
            F: FnOnce(io::Result<usize>, UserBuf) + Send + 'static,
    {
        let mut write_buf = ManuallyDrop::new(write_buf);
        let ptr = write_buf.as_mut_ptr();
        let len = write_buf.len();
        let cb = move |res| {
            let write_buf = ManuallyDrop::into_inner(write_buf);
            callback(res, write_buf);
        };
        unsafe { self.raw_write(fd, ptr, len, Some(cb.into())) }
    }

    /// Sends an asynchronous `flush` usercall. `callback` is called when a
    /// return value is received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn flush<F>(&self, fd: Fd, callback: F)
        where
            F: FnOnce(io::Result<()>) + Send + 'static,
    {
        unsafe {
            self.raw_flush(fd, Some(callback.into()));
        }
    }

    /// Sends an asynchronous `close` usercall. If specified, `callback` is
    /// called when a return is received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn close<F>(&self, fd: Fd, callback: Option<F>)
        where
            F: FnOnce() + Send + 'static,
    {
        let cb = callback.map(|callback| move |()| callback());
        unsafe {
            self.raw_close(fd, cb.map(Into::into));
        }
    }

    /// Sends an asynchronous `bind_stream` usercall. `callback` is called when
    /// a return value is received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn bind_stream<F>(&self, addr: &str, callback: F)
        where
            F: FnOnce(io::Result<TcpListener>) + Send + 'static,
    {
        // `User::<[u8]>::uninitialized` causes a synchronous usercall when dropped.
        // See: https://github.com/fortanix/rust-sgx/issues/531
        let mut addr_buf = ManuallyDrop::new(MakeSend::new(User::<[u8]>::uninitialized(addr.len())));
        let mut local_addr_buf = ManuallyDrop::new(MakeSend::new(User::<ByteBuffer>::uninitialized()));

        addr_buf[0..addr.len()].copy_from_enclave(addr.as_bytes());
        let addr_buf_ptr = addr_buf.as_raw_mut_ptr() as *mut u8;
        let local_addr_ptr = local_addr_buf.as_raw_mut_ptr();

        let cb = move |res: io::Result<Fd>| {
            // `_addr_buf` is of type `MakeSend<_>`, which will lead to a synchronous usercall
            // upon being dropped.
            // See: https://github.com/fortanix/rust-sgx/issues/531
            let _addr_buf = ManuallyDrop::into_inner(addr_buf);
            // Same as above, synchronous usercall will happen upon dropping
            // See: https://github.com/fortanix/rust-sgx/issues/531
            let local_addr_buf = ManuallyDrop::into_inner(local_addr_buf);

            let local_addr = Some(string_from_bytebuffer(&local_addr_buf, "bind_stream", "local_addr"));
            let res = res.map(|fd| unsafe { TcpListener::from_raw_fd(fd, TcpListenerMetadata { local_addr }) });
            callback(res);
        };
        unsafe { self.raw_bind_stream(addr_buf_ptr, addr.len(), local_addr_ptr, Some(cb.into())) }
    }

    /// Sends an asynchronous `accept_stream` usercall. `callback` is called
    /// when a return value is received from userspace.
    ///
    /// Returns a handle that can be used to cancel the usercall if desired.
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn accept_stream<F>(&self, fd: Fd, callback: F) -> CancelHandle
        where
            F: FnOnce(io::Result<TcpStream>) + Send + 'static,
    {
        let mut local_addr_buf = ManuallyDrop::new(MakeSend::new(User::<ByteBuffer>::uninitialized()));
        let mut peer_addr_buf = ManuallyDrop::new(MakeSend::new(User::<ByteBuffer>::uninitialized()));

        let local_addr_ptr = local_addr_buf.as_raw_mut_ptr();
        let peer_addr_ptr = peer_addr_buf.as_raw_mut_ptr();

        let cb = move |res: io::Result<Fd>| {
            let local_addr_buf = ManuallyDrop::into_inner(local_addr_buf);
            let peer_addr_buf = ManuallyDrop::into_inner(peer_addr_buf);

            let local_addr = Some(string_from_bytebuffer(&*local_addr_buf, "accept_stream", "local_addr"));
            let peer_addr = Some(string_from_bytebuffer(&*peer_addr_buf, "accept_stream", "peer_addr"));
            let res = res.map(|fd| unsafe { TcpStream::from_raw_fd(fd, TcpStreamMetadata { local_addr, peer_addr }) });
            callback(res);
        };
        unsafe { self.raw_accept_stream(fd, local_addr_ptr, peer_addr_ptr, Some(cb.into())) }
    }

    /// Sends an asynchronous `connect_stream` usercall. `callback` is called
    /// when a return value is received from userspace.
    ///
    /// Returns a handle that can be used to cancel the usercall if desired.
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn connect_stream<F>(&self, addr: &str, callback: F) -> CancelHandle
        where
            F: FnOnce(io::Result<TcpStream>) + Send + 'static,
    {
        let mut addr_buf = ManuallyDrop::new(MakeSend::new(User::<[u8]>::uninitialized(addr.len())));
        let mut local_addr_buf = ManuallyDrop::new(MakeSend::new(User::<ByteBuffer>::uninitialized()));
        let mut peer_addr_buf = ManuallyDrop::new(MakeSend::new(User::<ByteBuffer>::uninitialized()));

        addr_buf[0..addr.len()].copy_from_enclave(addr.as_bytes());
        let addr_buf_ptr = addr_buf.as_raw_mut_ptr() as *mut u8;
        let local_addr_ptr = local_addr_buf.as_raw_mut_ptr();
        let peer_addr_ptr = peer_addr_buf.as_raw_mut_ptr();

        let cb = move |res: io::Result<Fd>| {
            let _addr_buf = ManuallyDrop::into_inner(addr_buf);
            let local_addr_buf = ManuallyDrop::into_inner(local_addr_buf);
            let peer_addr_buf = ManuallyDrop::into_inner(peer_addr_buf);

            let local_addr = Some(string_from_bytebuffer(&local_addr_buf, "connect_stream", "local_addr"));
            let peer_addr = Some(string_from_bytebuffer(&peer_addr_buf, "connect_stream", "peer_addr"));
            let res = res.map(|fd| unsafe { TcpStream::from_raw_fd(fd, TcpStreamMetadata { local_addr, peer_addr }) });
            callback(res);
        };
        unsafe { self.raw_connect_stream(addr_buf_ptr, addr.len(), local_addr_ptr, peer_addr_ptr, Some(cb.into())) }
    }

    /// Sends an asynchronous `alloc` usercall to allocate one instance of `T`
    /// in userspace. `callback` is called when a return value is received from
    /// userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn alloc<T, F>(&self, callback: F)
        where
            T: UserSafe,
            F: FnOnce(io::Result<User<T>>) + Send + 'static,
    {
        let cb = move |res: io::Result<*mut u8>| {
            let res = res.map(|ptr| unsafe { User::<T>::from_raw(ptr as _) });
            callback(res);
        };
        unsafe {
            self.raw_alloc(mem::size_of::<T>(), T::align_of(), Some(cb.into()));
        }
    }

    /// Sends an asynchronous `alloc` usercall to allocate a slice of `T` in
    /// userspace with the specified `len`. `callback` is called when a return
    /// value is received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn alloc_slice<T, F>(&self, len: usize, callback: F)
        where
            [T]: UserSafe,
            F: FnOnce(io::Result<User<[T]>>) + Send + 'static,
    {
        let cb = move |res: io::Result<*mut u8>| {
            let res = res.map(|ptr| unsafe { User::<[T]>::from_raw_parts(ptr as _, len) });
            callback(res);
        };
        unsafe {
            self.raw_alloc(len * mem::size_of::<T>(), <[T]>::align_of(), Some(cb.into()));
        }
    }

    /// Sends an asynchronous `free` usercall to deallocate the userspace
    /// buffer `buf`. If specified, `callback` is called when a return is
    /// received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn free<T, F>(&self, mut buf: User<T>, callback: Option<F>)
        where
            T: ?Sized + UserSafe,
            F: FnOnce() + Send + 'static,
    {
        let ptr = buf.as_raw_mut_ptr();
        let cb = callback.map(|callback| move |()| callback());
        unsafe {
            self.raw_free(
                buf.into_raw() as _,
                mem::size_of_val(&mut *ptr),
                T::align_of(),
                cb.map(Into::into),
            );
        }
    }

    /// Sends an asynchronous `insecure_time` usercall. `callback` is called
    /// when a return value is received from userspace.
    ///
    /// Please refer to the type-level documentation for general notes about
    /// callbacks.
    pub fn insecure_time<F>(&self, callback: F)
        where
            F: FnOnce((SystemTime, Option<InsecureTimeInfo>)) + Send + 'static,
    {
        let cb = move |(nanos_since_epoch, insecure_time_info_ptr): (u64, *const InsecureTimeInfo)| {
            let t = UNIX_EPOCH + Duration::from_nanos(nanos_since_epoch);
            let maybe_insecure_time_info = if insecure_time_info_ptr.is_null() {
                // Safety: The caller must ensure that ptr is non-null and valid.
                None
            } else {
                unsafe { Some(*insecure_time_info_ptr) }
            };
            callback((t, maybe_insecure_time_info));
        };
        unsafe {
            self.raw_insecure_time(Some(cb.into()));
        }
    }
}

// The code is similar to `rust-lang/sys/sgx/abi/usercalls/mod.rs`,
// see: https://github.com/fortanix/rust-sgx/issues/532
fn string_from_bytebuffer(buf: &UserRef<ByteBuffer>, usercall: &str, arg: &str) -> String {
    String::from_utf8(copy_user_buffer(buf))
        .unwrap_or_else(|_| panic!("Usercall {}: expected {} to be valid UTF-8", usercall, arg))
}

// The code is similar to `rust-lang/sys/sgx/abi/usercalls/mod.rs`,
// see: https://github.com/fortanix/rust-sgx/issues/532
fn copy_user_buffer(buf: &UserRef<ByteBuffer>) -> Vec<u8> {
    unsafe {
        let buf = buf.to_enclave();
        if buf.len > 0 {
            let user = User::from_raw_parts(buf.data as _, buf.len);
            let v = user.to_enclave();
            batch_drop(user);
            v
        } else {
            // Mustn't look at `data` or call `free` if `len` is `0`.
            Vec::new()
        }
    }
}