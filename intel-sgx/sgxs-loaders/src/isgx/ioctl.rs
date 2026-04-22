/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const SGX_IOCTL: u8        = 0xa4;
const SGX_IOCTL_CREATE: u8 = 0x00;
const SGX_IOCTL_ADD: u8    = 0x01;
const SGX_IOCTL_INIT: u8   = 0x02;
const SGX_IOCTL_EXTEND: u8 = 0x81;

// The enclave creation ioctl is the same in the Montgomery and Augusta
// families of the API.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CreateData {
    pub secs: *const sgx_isa::Secs, // with baseaddr set to actual base
}
ioctl_write_ptr!(create, SGX_IOCTL, SGX_IOCTL_CREATE, CreateData);
pub const SGX_IOC_ENCLAVE_CREATE: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_CREATE, size_of::<CreateData>());

pub mod montgomery {
    use super::{SGX_IOCTL, SGX_IOCTL_ADD, SGX_IOCTL_INIT};

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug)]
    pub struct AddData {
        pub dstpage: u64,
        pub srcpage: *const [u8; 4096],
        pub secinfo: *const sgx_isa::Secinfo,
        pub chunks: u16,
    }
    ioctl_write_ptr!(add, SGX_IOCTL, SGX_IOCTL_ADD, AddData);
    pub const SGX_IOC_ENCLAVE_ADD_PAGES: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_ADD, size_of::<AddData>());

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitDataWithToken {
        pub base: u64,
        pub sigstruct: *const sgx_isa::Sigstruct,
        pub einittoken: *const sgx_isa::Einittoken,
    }
    ioctl_write_ptr!(init_with_token, SGX_IOCTL, SGX_IOCTL_INIT, InitDataWithToken);
    pub const SGX_IOC_ENCLAVE_INIT_WITH_TOKEN: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_INIT, size_of::<InitDataWithToken>());

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub base: u64,
        pub sigstruct: *const sgx_isa::Sigstruct,
    }
    ioctl_write_ptr!(init, SGX_IOCTL, SGX_IOCTL_INIT, InitData);
    pub const SGX_IOC_ENCLAVE_INIT: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_INIT, size_of::<InitData>());
}

pub mod augusta {
    use super::{SGX_IOCTL, SGX_IOCTL_ADD, SGX_IOCTL_INIT, SGX_IOCTL_EXTEND};

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
    ioctl_readwrite!(add, SGX_IOCTL, SGX_IOCTL_ADD, AddData);
    pub const SGX_IOC_ENCLAVE_ADD_PAGES: u64 = request_code_readwrite!(SGX_IOCTL, SGX_IOCTL_ADD, size_of::<AddData>());

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct InitData {
        pub sigstruct: *const sgx_isa::Sigstruct,
    }
    ioctl_write_ptr!(init, SGX_IOCTL, SGX_IOCTL_INIT, InitData);
    pub const SGX_IOC_ENCLAVE_INIT: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_INIT, size_of::<InitData>());

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct SgxEnclaveExtend {
        pub offset: u64,
    }

    ioctl_write_ptr!(extend, SGX_IOCTL, SGX_IOCTL_EXTEND, SgxEnclaveExtend);
    pub const SGX_IOC_ENCLAVE_EXTEND: u64 = request_code_write!(SGX_IOCTL, SGX_IOCTL_EXTEND, size_of::<SgxEnclaveExtend>());
}
