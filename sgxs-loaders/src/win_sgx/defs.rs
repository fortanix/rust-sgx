use winapi::um::winnt::{PAGE_ENCLAVE_THREAD_CONTROL, PAGE_ENCLAVE_UNVALIDATED};

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
pub enum EnclaveType {
    Sgx = 0x01,
    Vbs = 0x10,
}
bitflags! {
    pub struct WinPageProperties: u32 {
        const PAGE_NOACCESS          = 0x01;
        const PAGE_READONLY          = 0x02;
        const PAGE_READWRITE         = 0x04;
        const PAGE_WRITECOPY         = 0x08;
        const PAGE_EXECUTE           = 0x10;
        const PAGE_EXECUTE_READ      = 0x20;
        const PAGE_EXECUTE_READWRITE = 0x40;
        const PAGE_EXECUTE_WRITECOPY = 0x80;
        const PAGE_GUARD             = 0x100;
        const PAGE_NOCACHE           = 0x200;
        const PAGE_WRITECOMBINE      = 0x400;
        const PAGE_TCS               = PAGE_ENCLAVE_THREAD_CONTROL;
        const PAGE_UNVALIDATED       = PAGE_ENCLAVE_UNVALIDATED;
    }
}