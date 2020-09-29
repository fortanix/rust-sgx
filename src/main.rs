#[macro_use]
extern crate nix;

use std::{fs::OpenOptions, os::unix::io::AsRawFd, ptr};

use nix::sys::mman::{mmap, ProtFlags as Prot, MapFlags as Map};
use sgx_isa::{Attributes, AttributesFlags, PageType, Secinfo, SecinfoFlags, Secs};

const SGX_IOCTL: u8 = 0xa4;

// The enclave creation ioctl is the same in the Montgomery and Augusta
// families of the API.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CreateData {
    pub secs: *const sgx_isa::Secs, // with baseaddr set to actual base
}
ioctl_write_ptr!(sgx_create, SGX_IOCTL, 0x00, CreateData);

//const SGX_PAGE_MEASURE: u64 = 0x01;

#[repr(align(4096))]
pub struct Align4096<T>(pub T);

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AddData {
    pub src: *const Align4096<[u8; 4096]>,
    pub offset: u64,
    pub length: u64,
    pub secinfo: *const sgx_isa::Secinfo,
    pub flags: u64,
    pub count: u64,
}
ioctl_readwrite!(sgx_add, SGX_IOCTL, 0x01, AddData);

fn main() {
    unsafe {
        // 1 Gigabyte
        const ENCLAVE_SIZE: usize = 1024*1024*1024;
        
        let device = OpenOptions::new().read(true).write(true).open("/dev/sgx/enclave").expect("open: SGX device");

        let ptr = mmap(
            ptr::null_mut(),
            ENCLAVE_SIZE * 2,
            Prot::PROT_NONE,
            Map::MAP_SHARED | Map::MAP_ANONYMOUS,
            0,
            0,
        ).expect("mmap: reserve memory for enclave");

        let ptr = ptr.add(ptr.align_offset(ENCLAVE_SIZE));

        let secs = Secs {
            baseaddr: ptr as _,
            size: ENCLAVE_SIZE as _,
            ssaframesize: 1,
            miscselect: Default::default(),
            attributes: Attributes {
                flags: AttributesFlags::MODE64BIT,
                xfrm: 3,
            },
            ..Default::default()
        };
        let createdata = CreateData { secs: &secs };
        sgx_create(device.as_raw_fd(), &createdata).expect("sgx_create");

        for base in (0..ENCLAVE_SIZE).step_by(0x1000) {
            let data = Align4096([0; 0x1000]);
            let secinfo = Secinfo {
                flags: SecinfoFlags::R | PageType::Reg.into(),
                ..Default::default()
            };
            let mut adddata = AddData {
                src: &data,
                offset: base as _,
                length: 0x1000,
                secinfo: &secinfo,
                flags: 0,
                count: 0,
            };
            sgx_add(device.as_raw_fd(), &mut adddata).expect(&format!("sgx_add: offset {:08x}", base));
            assert_eq!(adddata.length, adddata.count);

            mmap(
                ptr.offset(base as _),
                0x1000,
                Prot::PROT_READ,
                Map::MAP_SHARED | Map::MAP_FIXED,
                device.as_raw_fd(),
                0,
            ).expect(&format!("mmap: enclave page @ offset {:08x}", base));
        }
    }
}
