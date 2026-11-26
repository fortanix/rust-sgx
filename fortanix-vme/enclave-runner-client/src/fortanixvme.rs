use vsock::{self, Platform};

pub struct Fortanixvme;

impl Platform for Fortanixvme {
    fn last_os_error() -> vsock::Error {
        #[cfg(feature = "std")]
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        #[cfg(not(feature = "std"))]
        let errno = unsafe { *libc::__errno_location() };
        vsock::Error::SystemError(errno as i32)
    }
}