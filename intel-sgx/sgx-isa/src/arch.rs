/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use super::Enclu;
use core::arch::asm;

/// Group all functions and types that is already upstreamed in the sgxstd
#[cfg(all(target_env = "sgx", not(feature = "sgxstd")))]
mod upstream {
    use super::*;
    use core::mem::MaybeUninit;

    /// Wrapper struct to force 16-byte alignment.
    #[repr(align(16))]
    pub struct Align16<T>(pub T);

    /// Wrapper struct to force 128-byte alignment.
    #[repr(align(128))]
    pub struct Align128<T>(pub T);

    /// Wrapper struct to force 512-byte alignment.
    #[repr(align(512))]
    pub struct Align512<T>(pub T);

    /// Call the `EGETKEY` instruction to obtain a 128-bit secret key.
    pub fn egetkey(request: &Align512<[u8; 512]>) -> Result<Align16<[u8; 16]>, u32> {
        unsafe {
            let mut out = MaybeUninit::uninit();
            let error;

            asm!(
                // rbx is reserved by LLVM
                "xchg %rbx, {0}",
                "enclu",
                "mov {0}, %rbx",
                inout(reg) request => _,
                inlateout("eax") Enclu::EGetkey as u32 => error,
                in("rcx") out.as_mut_ptr(),
                options(att_syntax, nostack),
            );

            match error {
                0 => Ok(out.assume_init()),
                err => Err(err),
            }
        }
    }

    /// Call the `EREPORT` instruction.
    ///
    /// This creates a cryptographic report describing the contents of the current
    /// enclave. The report may be verified by the enclave described in
    /// `targetinfo`.
    pub fn ereport(
        targetinfo: &Align512<[u8; 512]>,
        reportdata: &Align128<[u8; 64]>,
    ) -> Align512<[u8; 432]> {
        unsafe {
            let mut report = MaybeUninit::uninit();

            asm!(
                // rbx is reserved by LLVM
                "xchg %rbx, {0}",
                "enclu",
                "mov {0}, %rbx",
                inout(reg) targetinfo => _,
                in("eax") Enclu::EReport as u32,
                in("rcx") reportdata,
                in("rdx") report.as_mut_ptr(),
                options(att_syntax, preserves_flags, nostack),
            );

            report.assume_init()
        }
    }
}

// Export the function in the `upstream` group if not using `sgxstd`
#[cfg(all(target_env = "sgx", not(feature = "sgxstd")))]
pub use self::upstream::*;

// Export function in the `fortanix_sgx::arch` namespace if using `sgxstd`
#[cfg(all(target_env = "sgx", feature = "sgxstd"))]
pub use std::os::fortanix_sgx::arch::*;

// Functions and types below is not yet upstreamed and will be added to the
// upstream in the future.

/// Wrapper struct to force 256-byte alignment.
#[repr(align(256))]
pub struct Align256<T>(pub T);

/// Call the `EVERIFYREPORT2` instruction to verify a REPORT MAC struct.
/// The concrete type is [`crate::ReportMac`].
pub fn everifyreport2(report_mac: &Align256<[u8; 256]>) -> Result<(), u32> {
    unsafe {
        let error: u32;
        asm!(
            "xchg %rbx, {0}",
            "enclu",
            "mov {0}, %rbx",
            "jz 1f",
            "xor %eax, %eax",
            "1:",
            inout(reg) report_mac => _,
            inlateout("eax") Enclu::EVerifyReport2 as u32 => error,
            options(att_syntax, nostack),
        );
        match error {
            0 => Ok(()),
            err => Err(err),
        }
    }
}
