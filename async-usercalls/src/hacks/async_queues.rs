use super::{Cancel, Return, Usercall};
use crate::duplicated::ReturnValue;
use fortanix_sgx_abi::FifoDescriptor;
use std::num::NonZeroU64;
use std::os::fortanix_sgx::usercalls;
use std::os::fortanix_sgx::usercalls::raw;
use std::{mem, ptr};

// TODO: remove these once support for cancel queue is added in `std::os::fortanix_sgx`

pub unsafe fn async_queues(
    usercall_queue: *mut FifoDescriptor<Usercall>,
    return_queue: *mut FifoDescriptor<Return>,
    cancel_queue: *mut FifoDescriptor<Cancel>,
) -> raw::Result {
    ReturnValue::from_registers(
        "async_queues",
        raw::do_usercall(
            NonZeroU64::new(raw::UsercallNrs::async_queues as _).unwrap(),
            usercall_queue as _,
            return_queue as _,
            cancel_queue as _,
            0,
            false,
        ),
    )
}

pub unsafe fn alloc_descriptor<T>() -> *mut FifoDescriptor<T> {
    usercalls::alloc(
        mem::size_of::<FifoDescriptor<T>>(),
        mem::align_of::<FifoDescriptor<T>>(),
    )
    .expect("failed to allocate userspace memory") as _
}

pub unsafe fn to_enclave<T>(ptr: *mut FifoDescriptor<T>) -> FifoDescriptor<T> {
    let mut dest: FifoDescriptor<T> = mem::zeroed();
    ptr::copy(
        ptr as *const u8,
        (&mut dest) as *mut FifoDescriptor<T> as *mut u8,
        mem::size_of_val(&mut dest),
    );
    usercalls::free(
        ptr as _,
        mem::size_of::<FifoDescriptor<T>>(),
        mem::align_of::<FifoDescriptor<T>>(),
    );
    dest
}
