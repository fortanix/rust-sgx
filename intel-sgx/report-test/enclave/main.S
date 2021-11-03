/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

.equ targetinfo, .+0x3000
.equ reportdata, targetinfo+512
.equ report, reportdata+512

/* extern "C" fn entry(report_out: *mut Report) */
mov %rcx, %r8  /* save user RIP */
/* call ENCLU[EREPORT] */
lea targetinfo(%rip), %rbx /* RBX = EREPORT TARGETINFO */
lea reportdata(%rip), %rcx /* RCX = EREPORT REPORTDATA */
lea report(%rip), %rdx     /* RDX = EREPORT OUTPUT */
xor %eax, %eax             /* ENCLU leaf 0 = EREPORT */
enclu
/* memcpy report to output buffer */
mov $432, %ecx             /* ECX = REP MOVSB number of bytes */
mov %rdx, %rsi             /* RSI = REP MOVSB source address */
/* keep %rdi */            /* RDI = REP MOVSB destination address */
rep movsb
/* call ENCLU[EEXIT] */
mov %r8, %rbx              /* EEXIT Target = restored user RIP */
xor %rdi, %rdi             /* RDI = 0 is normal (non-usercall) exit */
/* keep rsi */             /* RSI = return value, don't care */
/* keep rdx */             /* RDX = return value, don't care */
mov $4, %rax               /* ENCLU leaf 4 = EEXIT */
enclu
