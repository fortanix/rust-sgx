/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std;
use std::cell::RefCell;

use sgx_isa::Enclu;
use sgxs::loader::Tcs;
use usercalls::abi::DispatchResult;

pub(crate) type DebugBuffer = [u8; 1024];

pub(crate) fn enter<T: Tcs, F>(
    tcs: T,
    mut on_usercall: F,
    p1: u64,
    p2: u64,
    p3: u64,
    p4: u64,
    p5: u64,
    debug_buf: Option<&RefCell<DebugBuffer>>,
) -> (T, DispatchResult)
where
    F: FnMut(u64, u64, u64, u64, u64) -> DispatchResult,
{
    let mut result = coenter(tcs, p1, p2, p3, p4, p5, debug_buf);

    while let CoResult::Yield(usercall) = result {
        let (p1, p2, p3, p4, p5) = usercall.parameters();
        result = match on_usercall(p1, p2, p3, p4, p5) {
            Ok(ret) => usercall.coreturn(ret, debug_buf),
            Err(err) => return (usercall.tcs, Err(err)),
        }
    }

    match result {
        CoResult::Return((tcs, v1, v2)) => (tcs, Ok((v1, v2))),
        CoResult::Yield(_) => unreachable!(),
    }
}

#[derive(Debug)]
pub enum CoResult<Y, R> {
    Yield(Y),
    Return(R),
}

#[derive(Debug)]
pub struct Usercall<T: Tcs> {
    pub tcs: T,
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
    let sgx_result: u32;
    let mut _tmp: (u64, u64);

    unsafe {
        let mut uninit_debug_buf: DebugBuffer;
        let debug_buf = debug_buf.map(|r| r.borrow_mut());
        let debug_buf = match debug_buf {
            Some(mut buf) => buf.as_mut_ptr(),
            None => {
                uninit_debug_buf = std::mem::uninitialized();
                uninit_debug_buf.as_mut_ptr()
            }
        };
        asm!("
        lea 1f(%rip),%rcx
1:
        enclu
"       : "={eax}"(sgx_result), "={rbx}"(_tmp.0), "={r10}"(_tmp.1),
              "={rdi}"(p1), "={rsi}"(p2), "={rdx}"(p3), "={r8}"(p4), "={r9}"(p5)
            : "{eax}" (2), "{rbx}"(tcs.address()), "{r10}"(debug_buf),
              "{rdi}"(p1), "{rsi}"(p2), "{rdx}"(p3), "{r8}"(p4), "{r9}"(p5)
            : "rcx", "r11", "memory"
            : "volatile"
        )
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
