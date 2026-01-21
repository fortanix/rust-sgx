/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
***/

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "large_array_derive")]
#[macro_export]
macro_rules! impl_default_clone_eq {
    ($n:ident) => {};
}

#[cfg(not(feature = "large_array_derive"))]
#[macro_export]
macro_rules! impl_default_clone_eq {
    ($t:ident) => {
        impl Default for $t {
            fn default() -> $t {
                unsafe { ::core::mem::zeroed() }
            }
        }
        impl Clone for $t {
            fn clone(&self) -> $t {
                unsafe { ::core::ptr::read(self) }
            }
        }
        impl PartialEq for $t {
            fn eq(&self, other: &$t) -> bool {
                unsafe {
                    let lhs: &[u8; Self::UNPADDED_SIZE] = ::core::mem::transmute(self);
                    let rhs: &[u8; Self::UNPADDED_SIZE] = ::core::mem::transmute(other);
                    lhs.get(..) == rhs.get(..)
                }
            }
        }
        // This cannot be derived because the derivation asserts that the members are Eq.
        impl Eq for $t {}
    }
}


#[macro_export]
macro_rules! struct_def {
    (
        $(#[doc = $doc:expr])*
        #[repr(C $(, align($align:tt))*)]
        $(#[cfg_attr(feature = "large_array_derive", derive($($cfgderive:meta),*))])*
        $(#[cfg_attr(feature = "serde", derive($($serdederive:meta),*))])*
        $(#[derive($($derive:meta),*)])*
        pub struct $name:ident $impl:tt
    ) => {
        $(
            impl_default_clone_eq!($name);
            #[cfg_attr(feature = "large_array_derive", derive($($cfgderive),*))]
        )*
        #[repr(C $(, align($align))*)]
        $(#[cfg_attr(feature = "serde", derive($($serdederive),*))])*
        $(#[derive($($derive),*)])*
        $(#[doc = $doc])*
        pub struct $name $impl

        impl $name {
            /// If `src` has the correct length for this type, returns `Some<T>`
            /// copied from `src`, else returns `None`.
            pub fn try_copy_from(src: &[u8]) -> Option<Self> {
                if src.len() == Self::UNPADDED_SIZE {
                    unsafe {
                        let mut ret : Self = ::core::mem::zeroed();
                        ::core::ptr::copy_nonoverlapping(src.as_ptr(),
                                                         &mut ret as *mut _ as *mut _,
                                                         Self::UNPADDED_SIZE);
                        Some(ret)
                    }
                } else {
                    None
                }
            }

            // Compile time check that the size argument is correct.
            // Not otherwise used.
            fn _type_tests() {
                #[repr(C)]
                $(#[cfg_attr(feature = "serde", derive($($serdederive),*))])*
                struct _Unaligned $impl

                impl _Unaligned {
                    fn _check_size(self) -> [u8; $name::UNPADDED_SIZE] {
                        unsafe { ::core::mem::transmute(self) }
                    }
                }

                // Should also check packed size against unaligned size here,
                // but Rust doesn't allow packed structs to contain aligned
                // structs, so this can't be tested.
            }
        }

        $(
        // check that alignment is set correctly
        #[test]
        #[allow(non_snake_case)]
        fn $name() {
            assert_eq!($align, ::core::mem::align_of::<$name>());
        }
        )*

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                unsafe {
                    slice::from_raw_parts(self as *const $name as *const u8, Self::UNPADDED_SIZE)
                }
            }
        }

        struct_def!(@align bytes $($align)* name $name);
    };
    (@align bytes 16 name $name:ident) => {
        struct_def!(@align type Align16 name $name);
    };
    (@align bytes 128 name $name:ident) => {
        struct_def!(@align type Align128 name $name);
    };
    (@align bytes 512 name $name:ident) => {
        struct_def!(@align type Align512 name $name);
    };
    (@align bytes $($other:tt)*) => {};
    (@align type $ty:ident name $name:ident) => {
        #[cfg(target_env = "sgx")]
        impl AsRef<arch::$ty<[u8; $name::UNPADDED_SIZE]>> for $name {
            fn as_ref(&self) -> &arch::$ty<[u8; $name::UNPADDED_SIZE]> {
                unsafe {
                    &*(self as *const _ as *const _)
                }
            }
        }
    };
}
