use std::ops::{Deref, DerefMut};
use std::os::fortanix_sgx::usercalls::alloc::User;
use std::os::fortanix_sgx::usercalls::raw::ByteBuffer;

pub(crate) trait MakeSendMarker {}

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
