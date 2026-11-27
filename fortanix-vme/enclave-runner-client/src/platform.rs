use vsock::{self, Platform};

/// [`vsock::Platform`] for this crate: tells `vsock` how to read `errno`
/// after a failed socket call.
///
/// Uses `std::io::Error::last_os_error` with the `std` feature, and libc's
/// `__errno_location` without it (e.g. when built as part of std via
/// `rustc-dep-of-std`).
///
/// Returns `SystemError(0)` if the OS reports no error code, where
/// `vsock::Std` would panic.
pub(crate) struct ClientPlatform;

impl Platform for ClientPlatform {
    fn last_os_error() -> vsock::Error {
        #[cfg(feature = "std")]
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        #[cfg(not(feature = "std"))]
        // SAFETY: `__errno_location` returns a valid pointer to this thread's errno.
        let errno = unsafe { *libc::__errno_location() };
        vsock::Error::SystemError(errno as i32)
    }
}