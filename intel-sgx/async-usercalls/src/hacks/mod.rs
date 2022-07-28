use std::ops::{Deref, DerefMut};
use std::os::fortanix_sgx::usercalls::alloc::{User, UserSafeSized};
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;

mod async_queues;

pub use self::async_queues::{alloc_descriptor, async_queues, to_enclave};

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
pub struct Cancel;

unsafe impl UserSafeSized for Cancel {}

pub(crate) trait MakeSendMarker {}

// Interim solution until we mark the target types appropriately
pub(crate) struct MakeSend<T: MakeSendMarker>(T);

impl<T: MakeSendMarker> MakeSend<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    #[allow(unused)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: MakeSendMarker> Deref for MakeSend<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: MakeSendMarker> DerefMut for MakeSend<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

unsafe impl<T: MakeSendMarker> Send for MakeSend<T> {}

impl MakeSendMarker for ByteBuffer {}
impl MakeSendMarker for User<ByteBuffer> {}
impl MakeSendMarker for User<[u8]> {}
