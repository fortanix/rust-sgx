/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std;
use std::cell::RefCell;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::Write;
use std::os::raw::c_void;

use sgx_isa::Enclu;
use sgxs::loader::Tcs;

pub(crate) type DebugBuffer = [u8; 1024];

#[derive(Debug)]
pub enum CoResult<Y, R> {
    Yield(Y),
    Return(R),
}

#[derive(Debug)]
pub struct Usercall<T: Tcs> {
    tcs: T,
    parameters: (u64, u64, u64, u64, u64),
}

pub type ThreadResult<T> = CoResult<Usercall<T>, (T, u64, u64)>;

impl<T: Tcs> Usercall<T> {
    pub fn parameters(&self) -> (u64, u64, u64, u64, u64) {
        self.parameters
    }

    pub fn coreturn(
        self,
        retval: (u64, u64),
        debug_buf: Option<&RefCell<DebugBuffer>>,
    ) -> ThreadResult<T> {
        coenter(self.tcs, 0, retval.0, retval.1, 0, 0, debug_buf)
    }

    pub fn tcs_address(&self) -> *mut c_void {
        self.tcs.address()
    }
}

pub(crate) fn coenter<T: Tcs>(
    tcs: T,
    mut p1: u64,
    mut p2: u64,
    mut p3: u64,
    mut p4: u64,
    mut p5: u64,
    debug_buf: Option<&RefCell<DebugBuffer>>,
) -> ThreadResult<T> {
    /// Check if __vdso_sgx_enter_enclave exists. We're using weak linkage, so
    /// it might not.
    #[cfg(target_os = "linux")]
    fn has_vdso_sgx_enter_enclave() -> bool {
        unsafe {
            let addr: usize;
            asm!("
.weak __vdso_sgx_enter_enclave
.type __vdso_sgx_enter_enclave, function
                mov __vdso_sgx_enter_enclave@GOTPCREL(%rip), {}
                jmp 1f

                // Strongly link to another symbol in the VDSO, so that the
                // linker will include a DT_NEEDED entry for `linux-vdso.so.1`.
                // This doesn't happen automatically because rustc passes
                // `--as-needed` to the linker. This is never executed because
                // of the unconditional jump above.
.global __vdso_clock_gettime
.type __vdso_clock_gettime, function
                call __vdso_clock_gettime@PLT

1:
                ", out(reg) addr, options(nomem, nostack, att_syntax));
            addr != 0
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn has_vdso_sgx_enter_enclave() -> bool {
        false
    }

    let sgx_result: u32;

    unsafe {
        let mut uninit_debug_buf: std::mem::MaybeUninit<DebugBuffer>;
        let mut debug_buf = debug_buf.map(|r| r.borrow_mut());
        let debug_buf_ptr = match debug_buf {
            Some(ref mut buf) => buf.as_mut_ptr(),
            None => {
                uninit_debug_buf = std::mem::MaybeUninit::uninit();
                uninit_debug_buf.as_mut_ptr() as *mut _
            }
        };
        if has_vdso_sgx_enter_enclave() {
            #[repr(C)]
            #[derive(Default)]
            struct SgxEnclaveRun {
                tcs: u64,
                function: u32,
                exception_vector: u16,
                exception_error_code: u16,
                exception_addr: u64,
                user_handler: u64,
                user_data: u64,
                reserved: [u64; 27],
            };

            impl fmt::Debug for SgxEnclaveRun {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    let function = Enclu::try_from(self.function);
                    let fundbg = match &function {
                        Ok(v) => v as &dyn fmt::Debug,
                        Err(_) => &self.function,
                    };
                    f.debug_struct("SgxEnclaveRun")
                        .field("function", fundbg)
                        .field("exception_vector", &self.exception_vector)
                        .field("exception_error_code", &self.exception_error_code)
                        .field("exception_addr", &(self.exception_addr as *mut ()))
                        .finish()
                }
            }

            let mut run = SgxEnclaveRun {
                tcs: tcs.address() as _,
                ..Default::default()
            };
            let ret: i32;
            asm!("
                    sub $0x8, %rsp                   // align stack
                    push {}                          // push argument: run
.weak __vdso_sgx_enter_enclave
.type __vdso_sgx_enter_enclave, function
                    call __vdso_sgx_enter_enclave@PLT
                    add $0x10, %rsp                  // restore stack pointer
                ",
                in(reg) &mut run,
                lateout("eax") ret,
                /* rbx unused */
                inout("rcx") Enclu::EEnter as u64 => _,
                inout("rdx") p3,
                inout("rdi") p1,
                inout("rsi") p2,
                inout("r8") p4,
                inout("r9") p5,
                inout("r10") debug_buf_ptr => _,
                lateout("r11") _,
                lateout("r12") _, // these may be clobbered in case of AEX
                lateout("r13") _, // V
                lateout("r14") _, // V
                lateout("r15") _, // V
                options(att_syntax)
            );
            if ret == 0 {
                sgx_result = run.function;
                match sgx_result.try_into() {
                    Ok(Enclu::EExit) => { /* normal case */ },
                    Ok(Enclu::EResume) => {
                        if let Some(mut debug_buf) = debug_buf {
                            let _ = write!(&mut debug_buf[..], "Enclave triggered exception: {:?}\0", run);
                        } else {
                            eprintln!("Enclave triggered exception, treating as panic: {:?}", run);
                        }
                        return CoResult::Yield(Usercall {
                            tcs: tcs,
                            parameters: (crate::usercalls::abi::UsercallList::exit as _, true as _, 0, 0, 0),
                        });
                    },
                    _ => panic!("Error entering enclave (VDSO): ret = success, run = {:?}", run),
                }
            } else {
                panic!("Error entering enclave (VDSO): ret = {:?}, run = {:?}", std::io::Error::from_raw_os_error(-ret), run);
            }
        } else {
            asm!("
                    lea 1f(%rip), %rcx // set SGX AEP
1:                  enclu
                ",
                inout("eax") Enclu::EEnter as u32 => sgx_result,
                inout("rbx") tcs.address() => _,
                out("rcx") _,
                inout("rdx") p3,
                inout("rdi") p1,
                inout("rsi") p2,
                inout("r8") p4,
                inout("r9") p5,
                inout("r10") debug_buf_ptr => _,
                out("r11") _,
                options(nostack, att_syntax)
            );
        }
    };

    if sgx_result != (Enclu::EExit as u32) {
        panic!("Invalid return value in EAX! eax={}", sgx_result);
    }

    if p1 == 0 {
        CoResult::Return((tcs, p2, p3))
    } else {
        CoResult::Yield(Usercall {
            tcs: tcs,
            parameters: (p1, p2, p3, p4, p5),
        })
    }
}
