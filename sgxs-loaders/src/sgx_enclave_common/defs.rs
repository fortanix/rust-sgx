/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![allow(unused)]

use abi::{Secs, Sigstruct};
use std::os::raw::c_void;

pub const ENCLAVE_ERROR_SUCCESS: u32 = 0;
pub const ENCLAVE_NOT_SUPPORTED: u32 = 1;
pub const ENCLAVE_INVALID_SIG_STRUCT: u32 = 2;
pub const ENCLAVE_INVALID_SIGNATURE: u32 = 3;
pub const ENCLAVE_INVALID_ATTRIBUTE: u32 = 4;
pub const ENCLAVE_INVALID_MEASUREMENT: u32 = 5;
pub const ENCLAVE_NOT_AUTHORIZED: u32 = 6;
pub const ENCLAVE_INVALID_ENCLAVE: u32 = 7;
pub const ENCLAVE_LOST: u32 = 8;
pub const ENCLAVE_INVALID_PARAMETER: u32 = 9;
pub const ENCLAVE_OUT_OF_MEMORY: u32 = 10;
pub const ENCLAVE_DEVICE_NO_RESOURCES: u32 = 11;
pub const ENCLAVE_ALREADY_INITIALIZED: u32 = 12;
pub const ENCLAVE_INVALID_ADDRESS: u32 = 13;
pub const ENCLAVE_RETRY: u32 = 14;
pub const ENCLAVE_INVALID_SIZE: u32 = 15;
pub const ENCLAVE_NOT_INITIALIZED: u32 = 16;
pub const ENCLAVE_UNEXPECTED: u32 = 0x1001;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum EnclaveType {
    Sgx1 = 1,
    Sgx2 = 2,
}

bitflags! {
    pub struct PageProperties: u32 {
        const R           = 0x00_01;
        const W           = 0x00_02;
        const X           = 0x00_04;
        const TCS         = 0x01_00;
        const UNVALIDATED = 0x10_00;
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum InfoType {
    EnclaveLaunchToken = 1,
}

pub const LIBRARY: &str = "libsgx_enclave_common.so.1";

pub const SYM_ENCLAVE_CREATE: &[u8] = b"enclave_create\0";
pub type EnclaveCreateFn = unsafe extern "C" fn(
    base_address: *mut c_void,
    virtual_size: usize,
    initial_commit: usize,
    type_: EnclaveType,
    info: &Secs,
    info_size: usize,
    enclave_error: Option<&mut u32>,
) -> *mut c_void;

pub const SYM_ENCLAVE_LOAD_DATA: &[u8] = b"enclave_load_data\0";
pub type EnclaveLoadDataFn = unsafe extern "C" fn(
    target_address: *mut c_void,
    target_size: usize,
    source_buffer: *const u8,
    data_properties: PageProperties,
    enclave_error: Option<&mut u32>,
) -> usize;

pub const SYM_ENCLAVE_INITIALIZE: &[u8] = b"enclave_initialize\0";
pub type EnclaveInitializeFn = unsafe extern "C" fn(
    base_address: *mut c_void,
    info: &Sigstruct,
    info_size: usize,
    enclave_error: Option<&mut u32>,
) -> bool;

pub const SYM_ENCLAVE_DELETE: &[u8] = b"enclave_delete\0";
pub type EnclaveDeleteFn =
    unsafe extern "C" fn(base_address: *mut c_void, enclave_error: Option<&mut u32>) -> bool;

pub const SYM_ENCLAVE_GET_INFORMATION: &[u8] = b"enclave_get_information\0";
pub type EnclaveGetInformationFn = unsafe extern "C" fn(
    base_address: *mut c_void,
    info_type: InfoType,
    output_info: *mut c_void,
    output_info_size: &mut usize,
    enclave_error: Option<&mut u32>,
) -> bool;

pub const SYM_ENCLAVE_SET_INFORMATION: &[u8] = b"enclave_set_information\0";
pub type EnclaveSetInformationFn = unsafe extern "C" fn(
    base_address: *mut c_void,
    info_type: InfoType,
    input_info: *const c_void,
    input_info_size: usize,
    enclave_error: Option<&mut u32>,
) -> bool;
