use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_env = "sgx")]
use std::os::fortanix_sgx::usercalls::alloc::UserSafeSized;

#[cfg(not(target_env = "sgx"))]
pub trait UserSafeSized: Copy + Sized {}

#[cfg(not(target_env = "sgx"))]
impl<T> UserSafeSized for T where T: Copy + Sized {}

#[repr(C)]
pub struct WithId<T: Copy> {
    id: AtomicU64,
    data: T,
}

/// # Safety
///
/// Implementors of this trait should ensure that:
///
/// * `std::mem::transmute::<Self, WithId<Self::Data>>(...)` is safe.
/// * `Self` is `repr(C)` struct.
///
pub unsafe trait Identified: UserSafeSized {
    type Data: Copy + Sized + 'static;

    fn empty() -> Self;

    fn get_id_non_atomic(&self) -> u64;

    fn get_id(&self) -> u64 {
        unsafe {
            let self_with_id = &*(self as *const Self as *const WithId<Self::Data>);
            self_with_id.id.load(Ordering::SeqCst)
        }
    }

    fn set_id(&self, id: u64) {
        unsafe {
            let self_with_id = &*(self as *const Self as *const WithId<Self::Data>);
            self_with_id.id.store(id, Ordering::SeqCst);
        }
    }

    fn copy_except_id(&mut self, from: &Self) {
        unsafe {
            let self_with_id = &mut *(self as *mut Self as *mut WithId<Self::Data>);
            let from_with_id = &*(from as *const Self as *const WithId<Self::Data>);
            self_with_id.data = from_with_id.data;
        }
    }
}

// This macro expects T to be defined as:
// ```
// struct $t {
//     pub $id: u64,
//     pub $data: $data_type,
// }
// ```
macro_rules! impl_identified {
    ($t:ty, $id:ident, $data:ident : $data_type:ty) => {
        unsafe impl Identified for $t {
            type Data = $data_type;

            fn empty() -> Self {
                fn _assert_transmute_safety() {
                    use std::mem::{forget, transmute, zeroed};
                    unsafe {
                        forget::<WithId<$data_type>>(transmute(zeroed::<$t>()));
                    }
                }
                Self {
                    $id: 0u64,
                    $data: <$data_type>::default(),
                }
            }

            fn get_id_non_atomic(&self) -> u64 {
                self.$id
            }
        }

        impl $crate::Identified for $t {}
    };
}

#[cfg(not(target_env = "sgx"))]
impl_identified! {fortanix_sgx_abi::Usercall, id, args: (u64, u64, u64, u64, u64)}
#[cfg(not(target_env = "sgx"))]
impl_identified! {fortanix_sgx_abi::Return, id, value: (u64, u64)}

#[cfg(target_env = "sgx")]
impl_identified! {std::os::fortanix_sgx::usercalls::raw::Usercall, id, args: (u64, u64, u64, u64, u64)}
#[cfg(target_env = "sgx")]
impl_identified! {std::os::fortanix_sgx::usercalls::raw::Return, id, value: (u64, u64)}

#[cfg(test)]
impl_identified! {crate::test_support::TestValue, id, val: u64}

#[cfg(all(test, target_env = "sgx"))]
unsafe impl UserSafeSized for crate::test_support::TestValue {}
