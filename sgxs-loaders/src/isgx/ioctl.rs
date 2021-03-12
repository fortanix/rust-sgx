/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const SGX_IOCTL: u8 = 0xa4;

// The enclave creation ioctl is the same in the Montgomery and Augusta
// families of the API.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CreateData {
    pub secs: *const sgx_isa::Secs, // with baseaddr set to actual base
}
ioctl_write_ptr!(create, SGX_IOCTL, 0x00, CreateData);

pub mod montgomery {
    use super::SGX_IOCTL;

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct AddData {
        pub dstpage: u64,
        pub srcpage: *const [u8; 4096],
        pub secinfo: *const sgx_isa::Secinfo,
        pub chunks: u16,
    }
    ioctl_write_ptr!(add, SGX_IOCTL, 0x01, AddData);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitDataWithToken {
        pub base: u64,
        pub sigstruct: *const sgx_isa::Sigstruct,
        pub einittoken: *const sgx_isa::Einittoken,
    }
    ioctl_write_ptr!(init_with_token, SGX_IOCTL, 0x02, InitDataWithToken);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub base: u64,
        pub sigstruct: *const sgx_isa::Sigstruct,
    }
    ioctl_write_ptr!(init, SGX_IOCTL, 0x02, InitData);
}

pub mod augusta {
    use super::SGX_IOCTL;

    bitflags! {
        pub struct SgxPageFlags: u64 {
            const SGX_PAGE_MEASURE = 0x01;
        }
    }

    #[repr(align(4096))]
    pub struct Align4096<T>(pub T);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct AddData {
        pub src: *const Align4096<[u8; 4096]>,
        pub offset: u64,
        pub length: u64,
        pub secinfo: *const sgx_isa::Secinfo,
        pub flags: SgxPageFlags,
        pub count: u64,
    }
    ioctl_readwrite!(add, SGX_IOCTL, 0x01, AddData);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct ExtendData {
        pub offset: u64,
    }
    ioctl_readwrite!(extend, SGX_IOCTL, 0x04, ExtendData);

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub sigstruct: *const sgx_isa::Sigstruct,
    }
    ioctl_write_ptr!(init, SGX_IOCTL, 0x02, InitData);
}
