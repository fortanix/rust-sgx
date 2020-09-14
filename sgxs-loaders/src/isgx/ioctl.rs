/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct CreateData {
    pub secs: *const sgx_isa::Secs, // with baseaddr set to actual base
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct AddData {
    pub dstpage: u64,
    pub srcpage: *const [u8; 4096],
    pub secinfo: *const sgx_isa::Secinfo,
    pub chunks: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct InitDataWithToken {
    pub base: u64,
    pub sigstruct: *const sgx_isa::Sigstruct,
    pub einittoken: *const sgx_isa::Einittoken,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct InitData {
    pub base: u64,
    pub sigstruct: *const sgx_isa::Sigstruct,
}

const SGX_IOCTL: u8 = 0xa4;
ioctl_write_ptr!(create, SGX_IOCTL, 0x00, CreateData);
ioctl_write_ptr!(add, SGX_IOCTL, 0x01, AddData);
ioctl_write_ptr!(init_with_token, SGX_IOCTL, 0x02, InitDataWithToken);
ioctl_write_ptr!(init, SGX_IOCTL, 0x02, InitData);
