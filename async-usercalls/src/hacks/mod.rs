use std::ops::{Deref, DerefMut};
use std::os::fortanix_sgx::usercalls::alloc::UserSafeSized;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;

mod async_queues;
mod unsafe_typecasts;

pub use self::async_queues::{alloc_descriptor, async_queues, to_enclave};
pub use self::unsafe_typecasts::{new_std_listener, new_std_stream};

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Usercall(pub u64, pub u64, pub u64, pub u64, pub u64);

unsafe impl UserSafeSized for Usercall {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Return(pub u64, pub u64);

unsafe impl UserSafeSized for Return {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Cancel {
    /// Reserved for future use.
    pub reserved: u64,
}

unsafe impl UserSafeSized for Cancel {}

// Interim solution until we mark the target types appropriately
pub(crate) struct MakeSend<T>(T);

impl<T> MakeSend<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    #[allow(unused)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for MakeSend<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for MakeSend<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

unsafe impl Send for MakeSend<ByteBuffer> {}
unsafe impl Send for MakeSend<crate::alloc::User<ByteBuffer>> {}
