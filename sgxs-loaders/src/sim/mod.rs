/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! A simulator for SGX enclaves.
//!
//! This simulator only works for enclaves that don't use FS.
//!
//! **Note**: Using this module will install various signal handlers. These
//! might conflict with other signal handlers your application uses.

use std::{alloc, cell::Cell, io, num::NonZeroU64, ptr};
use std::collections::{HashMap, BTreeMap};
use std::sync::{Mutex, MutexGuard};

use libc::{self, c_int, c_void, c_ulong};
use ioctl_crate::sys::signal::{self, sigaction, SigHandler, SigAction, SaFlags, SigSet, Signal};
use abi::{Enclu, Tcs};

mod loader;
pub use self::loader::{Error, Simulator};

lazy_static! {
    static ref SIMULATED_ENCLAVES: Mutex<BTreeMap<u64, Enclave>> = {
        init_signal_handlers();
        Default::default()
    };
}

#[derive(Debug, Copy, Clone)]
enum TcsState {
    NotEntered,
    Entered {
        oldgs: u64,
        aep: u64,
    }
}

impl Default for TcsState {
    fn default() -> Self {
        TcsState::NotEntered
    }
}

#[derive(Debug, Default)]
struct Enclave {
    base: u64,
    size: u64,
    tcss: HashMap<u64, TcsState>,
}

const ENCLU: [u8; 3] = [0x0f, 0x01, 0xd7];

fn find_enclave_by_address<'a>(map: &'a mut MutexGuard<'static, BTreeMap<u64, Enclave>>, address: u64) -> Option<&'a mut Enclave> {
    map.range_mut(..address)
        .next_back()
        .and_then(|(_, enclave)| {
            if enclave.base <= address && (enclave.base + enclave.size) > address {
                Some(enclave)
            } else {
                None
            }
        })
}

extern "C" fn handle_signal(signo: c_int, _info: *mut libc::siginfo_t, context: *mut c_void) {
    extern "C" {
        #[link_name = "arch_prctl"]
        fn arch_prctl_set(code: c_int, addr: c_ulong) -> c_int;
        #[link_name = "arch_prctl"]
        fn arch_prctl_get(code: c_int, addr: &mut c_ulong) -> c_int;
    }

    const ARCH_SET_GS: c_int = 0x1001;
    //const ARCH_SET_FS: c_int = 0x1002;
    //const ARCH_GET_FS: c_int = 0x1003;
    const ARCH_GET_GS: c_int = 0x1004;

    thread_local! {
        pub static IN_TCS: Cell<Option<NonZeroU64>> = Cell::new(None);
    }

    unsafe {
        let context = &mut *(context as *mut libc::ucontext_t);

        let rip = context.uc_mcontext.gregs[Greg::RIP as usize] as u64;
        let insn_is_enclu = ptr::read(rip as *const [u8; 3]) == ENCLU;
        let insn_in_enclave = find_enclave_by_address(&mut SIMULATED_ENCLAVES.lock().unwrap(), rip).map(|e| e.base);

        match (insn_is_enclu, insn_in_enclave) {
            (true, None) => {
                let rax = context.uc_mcontext.gregs[Greg::RAX as usize];
                if rax == Enclu::EEnter as i64 || rax == Enclu::EResume as i64 {
                    let rbx = context.uc_mcontext.gregs[Greg::RBX as usize] as u64;
                    let rcx = context.uc_mcontext.gregs[Greg::RBX as usize] as u64;
                    if let Some(enclave) = find_enclave_by_address(&mut SIMULATED_ENCLAVES.lock().unwrap(), rbx) {
                        if let Some(tcsstate) = enclave.tcss.get_mut(&rbx) {
                            if rax == Enclu::EResume as i64 {
                                unimplemented!("simulate ENCLU[ERESUME]");
                            }
                            if let TcsState::Entered { .. } = tcsstate  {
                                panic!("Tried to enter already-entered TCS in simulated enclave: 0x{:x}", rbx);
                            }
                            let tcs = &*(rbx as *const Tcs);
                            let mut oldgs = 0;
                            if 0 != arch_prctl_get(ARCH_GET_GS, &mut oldgs) {
                                panic!("Failed to read GS: {}", io::Error::last_os_error());
                            }
                            *tcsstate = TcsState::Entered { oldgs, aep: rcx };
                            context.uc_mcontext.gregs[Greg::RAX as usize] = 1; // ERESUME not supported
                            context.uc_mcontext.gregs[Greg::RCX as usize] = (rip + ENCLU.len() as u64) as _;
                            context.uc_mcontext.gregs[Greg::RIP as usize] = (enclave.base + tcs.oentry) as _;
                            if 0 != arch_prctl_set(ARCH_SET_GS, enclave.base + tcs.ogsbasgx) {
                                panic!("Failed to set GS: {}", io::Error::last_os_error());
                            }
                            IN_TCS.with(|in_tcs| if let Some(old_tcs) = in_tcs.replace(Some(NonZeroU64::new(rbx).unwrap())) {
                                panic!("OS thread already in TCS 0x{:x} while trying to enter TCS 0x{:x} in simulated enclave", old_tcs, rbx);
                            });
                            return;
                        } else {
                            panic!("Tried to enter invalid TCS in simulated enclave: 0x{:x}", rbx);
                        }
                    }
                }
            }
            (true, Some(base)) => {
                let rax = context.uc_mcontext.gregs[Greg::RAX as usize];
                if rax == Enclu::EExit as i64 {
                    let tcs = match IN_TCS.with(|in_tcs| in_tcs.take()) {
                        Some(tcs) => tcs.get(),
                        None => panic!("ENCLU[EEXIT] called while OS thread not in TCS (RIP=0x{:x})", rip),
                    };
                    let mut lock = SIMULATED_ENCLAVES.lock().unwrap();
                    let enclave = find_enclave_by_address(&mut lock, tcs).expect("Enclave not found");
                    let (oldgs, aep) = match enclave.tcss[&tcs] {
                        TcsState::Entered { oldgs, aep } => (oldgs, aep),
                        TcsState::NotEntered => panic!("Tried to exit TCS that wasn't entered in simulated enclave: 0x{:x}", tcs),
                    };
                    *enclave.tcss.get_mut(&tcs).unwrap() = TcsState::NotEntered;
                    context.uc_mcontext.gregs[Greg::RCX as usize] = aep as _;
                    context.uc_mcontext.gregs[Greg::RIP as usize] = context.uc_mcontext.gregs[Greg::RBX as usize];
                    if 0 != arch_prctl_set(ARCH_SET_GS, oldgs) {
                        panic!("Failed to set GS: {}", io::Error::last_os_error());
                    }
                    return;
                } else if rax == Enclu::EGetkey as i64 || rax == Enclu::EReport as i64 {
                    // FIXME: do something
                    return;
                }
            }
            (false, None) => {
                // not ENCLU, not in simulated enclave: not our concern
            }
            (false, Some(_)) => {
                unimplemented!("simulate AEX for TCS 0x{:x}", IN_TCS.with(|in_tcs| in_tcs.get()).unwrap().get())
            }
        }

        // case not handled by us, restore default signal handler (force exit)
        let sig = Signal::from_c_int(signo).unwrap();
        let sig_action = SigAction::new(
            SigHandler::SigDfl,
            SaFlags::empty(),
            SigSet::empty()
        );
        sigaction(sig, &sig_action).unwrap();
        signal::raise(sig).unwrap();
    }
}

fn init_signal_handlers() {
    unsafe {
        let layout = alloc::Layout::from_size_align_unchecked(libc::SIGSTKSZ, 1);
        let ss_sp = alloc::alloc(layout) as *mut libc::c_void;
        if ss_sp.is_null() {
            alloc::handle_alloc_error(layout);
        }

        if 0 != libc::sigaltstack(&libc::stack_t {
            ss_sp, ss_size: libc::SIGSTKSZ, ss_flags: 0
        }, ptr::null_mut()) {
            panic!("Failed to setup signal stack: {}", io::Error::last_os_error());
        }

        let sig_action = SigAction::new(
            SigHandler::SigAction(handle_signal),
            SaFlags::SA_ONSTACK,
            SigSet::empty()
        );
        sigaction(Signal::SIGSEGV, &sig_action).unwrap();
        sigaction(Signal::SIGILL, &sig_action).unwrap();
    }
}

#[repr(C)]
#[allow(unused)]
enum Greg {
    R8 = 0,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RDI,
    RSI,
    RBP,
    RBX,
    RDX,
    RAX,
    RCX,
    RSP,
    RIP,
    EFL,
    CSGSFS, /* Actually short cs, gs, fs, __pad0. */
    ERR,
    TRAPNO,
    OLDMASK,
    CR2,
}
