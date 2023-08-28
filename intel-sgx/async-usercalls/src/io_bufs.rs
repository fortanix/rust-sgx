use std::cell::UnsafeCell;
use std::cmp;
use std::io::IoSlice;
use std::ops::{Deref, DerefMut, Range};
use std::os::fortanix_sgx::usercalls::alloc::{User, UserRef};
use std::sync::Arc;

pub struct UserBuf(UserBufKind);

enum UserBufKind {
    Owned {
        user: User<[u8]>,
        range: Range<usize>,
    },
    Shared {
        user: Arc<UnsafeCell<User<[u8]>>>,
        range: Range<usize>,
    },
}

impl UserBuf {
    pub fn into_user(self) -> Result<User<[u8]>, Self> {
        match self.0 {
            UserBufKind::Owned { user, .. } => Ok(user),
            UserBufKind::Shared { user, range } => Err(Self(UserBufKind::Shared { user, range })),
        }
    }

    fn into_shared(self) -> Option<Arc<UnsafeCell<User<[u8]>>>> {
        match self.0 {
            UserBufKind::Owned { .. } => None,
            UserBufKind::Shared { user, .. } => Some(user),
        }
    }
}

unsafe impl Send for UserBuf {}

impl Deref for UserBuf {
    type Target = UserRef<[u8]>;

    fn deref(&self) -> &Self::Target {
        match self.0 {
            UserBufKind::Owned { ref user, ref range } => &user[range.start..range.end],
            UserBufKind::Shared { ref user, ref range } => {
                let user = unsafe { &*user.get() };
                &user[range.start..range.end]
            }
        }
    }
}

impl DerefMut for UserBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.0 {
            UserBufKind::Owned {
                ref mut user,
                ref range,
            } => &mut user[range.start..range.end],
            UserBufKind::Shared { ref user, ref range } => {
                let user = unsafe { &mut *user.get() };
                &mut user[range.start..range.end]
            }
        }
    }
}

impl From<User<[u8]>> for UserBuf {
    fn from(user: User<[u8]>) -> Self {
        UserBuf(UserBufKind::Owned {
            range: 0..user.len(),
            user,
        })
    }
}

impl From<(User<[u8]>, Range<usize>)> for UserBuf {
    fn from(pair: (User<[u8]>, Range<usize>)) -> Self {
        UserBuf(UserBufKind::Owned {
            user: pair.0,
            range: pair.1,
        })
    }
}

/// `WriteBuffer` provides a ring buffer that can be written to by the code
/// running in the enclave while a portion of it can be passed to a `write`
/// usercall running concurrently. It ensures that enclave code does not write
/// to the portion sent to userspace.
pub struct WriteBuffer {
    userbuf: Arc<UnsafeCell<User<[u8]>>>,
    buf_len: usize,
    read: u32,
    write: u32,
}

unsafe impl Send for WriteBuffer {}

impl WriteBuffer {
    pub fn new(userbuf: User<[u8]>) -> Self {
        Self {
            buf_len: userbuf.len(),
            userbuf: Arc::new(UnsafeCell::new(userbuf)),
            read: 0,
            write: 0,
        }
    }

    pub fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> usize {
        if self.is_full() {
            return 0;
        }
        let mut wrote = 0;
        for buf in bufs {
            wrote += self.write(buf);
        }
        wrote
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        let (_, write_offset) = self.offsets();
        let rem = self.remaining_capacity();
        let can_write = cmp::min(buf.len(), rem);
        let end = cmp::min(self.buf_len, write_offset + can_write);
        let n = end - write_offset;
        unsafe {
            let userbuf = &mut *self.userbuf.get();
            userbuf[write_offset..write_offset + n].copy_from_enclave(&buf[..n]);
        }
        self.advance_write(n);
        n + if n < can_write { self.write(&buf[n..]) } else { 0 }
    }

    /// This function returns a slice of bytes appropriate for writing to a socket.
    /// Once some or all of these bytes are successfully written to the socket,
    /// `self.consume()` must be called to actually consume those bytes.
    ///
    /// Returns None if the buffer is empty.
    ///
    /// Panics if called more than once in a row without either calling `consume()`
    /// or dropping the previously returned buffer.
    pub fn consumable_chunk(&mut self) -> Option<UserBuf> {
        assert!(
            Arc::strong_count(&self.userbuf) == 1,
            "called consumable_chunk() more than once in a row"
        );
        let range = match self.offsets() {
            (_, _) if self.read == self.write => return None, // empty
            (r, w) if r < w => r..w,
            (r, _) => r..self.buf_len,
        };
        Some(UserBuf(UserBufKind::Shared {
            user: self.userbuf.clone(),
            range,
        }))
    }

    /// Mark `n` bytes as consumed. `buf` must have been produced by a call
    /// to `self.consumable_chunk()`.
    /// Panics if:
    /// - `n > buf.len()`
    /// - `buf` was not produced by `self.consumable_chunk()`
    ///
    /// This function is supposed to be used in conjunction with `consumable_chunk()`.
    pub fn consume(&mut self, buf: UserBuf, n: usize) {
        assert!(n <= buf.len());
        const PANIC_MESSAGE: &'static str = "`buf` not produced by self.consumable_chunk()";
        let buf = buf.into_shared().expect(PANIC_MESSAGE);
        assert!(Arc::ptr_eq(&self.userbuf, &buf), "{}", PANIC_MESSAGE);
        drop(buf);
        assert!(Arc::strong_count(&self.userbuf) == 1, "{}", PANIC_MESSAGE);
        self.advance_read(n);
    }

    fn len(&self) -> usize {
        match self.offsets() {
            (_, _) if self.read == self.write => 0,                      // empty
            (r, w) if r == w && self.read != self.write => self.buf_len, // full
            (r, w) if r < w => w - r,
            (r, w) => w + self.buf_len - r,
        }
    }

    fn remaining_capacity(&self) -> usize {
        let len = self.len();
        debug_assert!(len <= self.buf_len);
        self.buf_len - len
    }

    fn offsets(&self) -> (usize, usize) {
        (self.read as usize % self.buf_len, self.write as usize % self.buf_len)
    }

    pub fn is_empty(&self) -> bool {
        self.read == self.write
    }

    fn is_full(&self) -> bool {
        let (read_offset, write_offset) = self.offsets();
        read_offset == write_offset && self.read != self.write
    }

    fn advance_read(&mut self, by: usize) {
        debug_assert!(by <= self.len());
        self.read = ((self.read as usize + by) % (self.buf_len * 2)) as _;
    }

    fn advance_write(&mut self, by: usize) {
        debug_assert!(by <= self.remaining_capacity());
        self.write = ((self.write as usize + by) % (self.buf_len * 2)) as _;
    }
}

pub struct ReadBuffer {
    userbuf: User<[u8]>,
    position: usize,
    len: usize,
}

impl ReadBuffer {
    /// Constructs a new `ReadBuffer`, assuming `len` bytes of `userbuf` have
    /// meaningful data. Panics if `len > userbuf.len()`.
    pub fn new(userbuf: User<[u8]>, len: usize) -> ReadBuffer {
        assert!(len <= userbuf.len());
        ReadBuffer {
            userbuf,
            position: 0,
            len,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        debug_assert!(self.position <= self.len);
        if self.position == self.len {
            return 0;
        }
        let n = cmp::min(buf.len(), self.len - self.position);
        self.userbuf[self.position..self.position + n].copy_to_enclave(&mut buf[..n]);
        self.position += n;
        n
    }

    /// Returns the number of bytes that have not been read yet.
    pub fn remaining_bytes(&self) -> usize {
        debug_assert!(self.position <= self.len);
        self.len - self.position
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Consumes self and returns the internal userspace buffer.
    /// It's the caller's responsibility to ensure all bytes have been read
    /// before calling this function.
    pub fn into_inner(self) -> User<[u8]> {
        self.userbuf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fortanix_sgx::usercalls::alloc::User;

    #[test]
    fn write_buffer_basic() {
        const LENGTH: usize = 1024;
        let mut write_buffer = WriteBuffer::new(User::<[u8]>::uninitialized(1024));

        let buf = vec![0u8; LENGTH];
        assert_eq!(write_buffer.write(&buf), LENGTH);
        assert_eq!(write_buffer.write(&buf), 0);

        let chunk = write_buffer.consumable_chunk().unwrap();
        write_buffer.consume(chunk, 200);
        assert_eq!(write_buffer.write(&buf), 200);
        assert_eq!(write_buffer.write(&buf), 0);
    }

    #[test]
    #[should_panic]
    fn call_consumable_chunk_twice() {
        const LENGTH: usize = 1024;
        let mut write_buffer = WriteBuffer::new(User::<[u8]>::uninitialized(1024));

        let buf = vec![0u8; LENGTH];
        assert_eq!(write_buffer.write(&buf), LENGTH);
        assert_eq!(write_buffer.write(&buf), 0);

        let chunk1 = write_buffer.consumable_chunk().unwrap();
        let _ = write_buffer.consumable_chunk().unwrap();
        drop(chunk1);
    }

    #[test]
    #[should_panic]
    fn consume_wrong_buf() {
        const LENGTH: usize = 1024;
        let mut write_buffer = WriteBuffer::new(User::<[u8]>::uninitialized(1024));

        let buf = vec![0u8; LENGTH];
        assert_eq!(write_buffer.write(&buf), LENGTH);
        assert_eq!(write_buffer.write(&buf), 0);

        let unrelated_buf: UserBuf = User::<[u8]>::uninitialized(512).into();
        write_buffer.consume(unrelated_buf, 100);
    }

    #[test]
    fn read_buffer_basic() {
        let mut buf = User::<[u8]>::uninitialized(64);
        const DATA: &'static [u8] = b"hello";
        buf[0..DATA.len()].copy_from_enclave(DATA);

        let mut read_buffer = ReadBuffer::new(buf, DATA.len());
        assert_eq!(read_buffer.len(), DATA.len());
        assert_eq!(read_buffer.remaining_bytes(), DATA.len());
        let mut buf = [0u8; 8];
        assert_eq!(read_buffer.read(&mut buf), DATA.len());
        assert_eq!(read_buffer.remaining_bytes(), 0);
        assert_eq!(&buf, b"hello\0\0\0");
    }
}