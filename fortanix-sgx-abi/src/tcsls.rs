
bitflags! {
    pub struct TcslsFlags: u16 {
        const SECONDARY_TCS  = 0b01; // 0 = standard TCS, 1 = secondary TCS
        const INIT_ONCE      = 0b10;
    }
}

#[derive(PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Tcsls {
    top_of_stack: u64,  // *offset* from image base to top of stack
    flags: TcslsFlags,
    user_fcw: u16,
    user_mxcsr: u16,
    last_rsp: u64,
    panic_last_rsp: u64,
    debug_panic_buf_ptr: u64,
    user_rsp: u64,
    user_retip: u64,
    user_rbp: u64,
    user_r12: u64,
    user_r13: u64,
    user_r14: u64,
    user_r15: u64,
    tls_ptr: u64,
    tcs_addr: u64,
}

impl Tcsls {
    // Creates a new TCSLS instance
    // `top_of_stack` *offset* from image base to top of stack
    pub fn new(top_of_stack: u64, flags: TcslsFlags) -> Tcsls {
        Tcsls {
            top_of_stack,
            flags,
            user_fcw: 0,
            user_mxcsr: 0,
            last_rsp: 0,
            panic_last_rsp: 0,
            debug_panic_buf_ptr: 0,
            user_rsp: 0,
            user_retip: 0,
            user_rbp: 0,
            user_r12: 0,
            user_r13: 0,
            user_r14: 0,
            user_r15: 0,
            tls_ptr: 0,
            tcs_addr: 0,
        }
    }
}
