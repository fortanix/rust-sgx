/*
 * The Rust secure enclave runtime and library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * When embedding this file in source code form in the object code of another
 * program, that other program is not considered to be based on this file for
 * purposes of the GNU Affero General Public License. The intention of this
 * clarification is to allow distributing this file with linking tools that are
 * not covered under the same license as this file, while requiring that
 * programs linked with this file adhere to the GNU Affero General Public
 * License.
 */

// When using this macro, don't forget to adjust the linker version script!
.macro globvar name size
	.global \name
	.protected \name
	.align \size
	.size \name , \size
	\name :
		.org .+\size
.endm

.section absolute
.global IMAGE_BASE
IMAGE_BASE:

.section .rodata
// The XSAVE area needs to be a large chunk of readable memory, but since we are
// going to restore everything to its initial state (XSTATE_BV=0), only certain
// parts need to have a defined value. In particular:
//
//   * MXCSR in the legacy area. This register is always restored if RFBM[1] or
//     RFBM[2] is set, regardless of the value of XSTATE_BV
//   * XSAVE header
.align 64
xsave_clear:
.org .+24
xsave_mxcsr:
	.int 0

// We can store a bunch of data in the gap between MXCSR and the XSAVE header
	globvar HEAP_BASE 8
	globvar HEAP_SIZE 8
	globvar RELA 8
	globvar RELACOUNT 8
	globvar ENCLAVE_SIZE 8
	globvar CFGDATA_BASE 8

.org xsave_clear+512
xsave_header:
	.int 0, 0 // XSTATE_BV
	.int 0, 0 // XCOMP_BV
	.org .+48 // reserved bits

.data
panicked:
	.byte 0

#ifdef DEBUG
.section .note.libenclave, "", @note
	.int 17 // namesz
	.int  0 // descsz
	.int  0 // type
	.asciz "libenclave DEBUG"
	.align 4
#endif

// TLS section
#define tls_tos        0x00 // initialized by loader to *offset* from image base to TOS
#define tls_init_once  0x08 // initialized by loader to 0
// 15 unused bits
#define tls_user_fcw   0x0a
#define tls_user_mxcsr 0x0c
#define tls_last_rsp   0x10 // initialized by loader to 0
#define tls_user_rsp   0x18
#define tls_user_retip 0x20
#define tls_user_rbp   0x28
#define tls_user_r12   0x30
#define tls_user_r13   0x38
#define tls_user_r14   0x40
#define tls_user_r15   0x48
#define tls_debug_panic_buf_ptr 0x50

/*************************
 ******* sgx_entry *******
 *************************
 * TCS.NSSA should be 1.
 *
 * >>calling convention<<
 *   parameters (in):
 *    - RDI
 *    - RSI
 *    - RDX
 *    - R8
 *    - R9
 *    - R10 (debug mode only)
 *   return value (out):
 *    - RDX (but see below for non-return exits)
 *   caller-saved registers:
 *    - ENCLU registers (EAX, RBX, RCX)
 *   callee-saved registers:
 *    - RSP, RBP
 *    - R12, R13, R14, R15
 *   flags affected:
 *    - CF, PF, AF, ZF, SF, OF, DF are cleared
 *   debug mode:
 *    - when compiled for debug, in R10, pass a pointer to a 1024-byte buffer
 *      which can be used to output debugging messages upon panic exit.
 *
 * >>non-return exit<<
 *   RDI indicates the type of exit
 *    - 0: normal exit
 *    - negative: panic exit, abort. If entered again, will panic exit again
 *    - any other value: “usercall”. After usercall handler, execute EENTER again.
 *
 * >>usercall calling convention<<
 *   parameters (in):
 *    - RDI
 *    - RSI
 *    - RDX
 *    - R8
 *    - R9
 *   return value (out):
 *    - RDX
 *   caller-saved registers:
 *    - all registers (callee can use any register)
 *
 *   RSP, RBP, R12, R13, R14, R15 are the same as when the enclave was entered
 *************************/

.text
.global sgx_entry
.type sgx_entry,function
sgx_entry:
// save user registers
	mov %rcx,%gs:tls_user_retip
	mov %rsp,%gs:tls_user_rsp
	mov %rbp,%gs:tls_user_rbp
	mov %r12,%gs:tls_user_r12
	mov %r13,%gs:tls_user_r13
	mov %r14,%gs:tls_user_r14
	mov %r15,%gs:tls_user_r15
	stmxcsr %gs:tls_user_mxcsr
	fnstcw %gs:tls_user_fcw
#ifdef DEBUG
	mov %r10,%gs:tls_debug_panic_buf_ptr
#endif
// check if returning from usercall
	mov %gs:tls_last_rsp,%r11
	test %r11,%r11
	jnz usercall_ret
// setup stack
	mov %gs:tls_tos,%rsp // initially, RSP is not set to the correct value
	                     // here. This is fixed below under "adjust stack".
// check for thread init
	bts $0,%gs:tls_init_once
	jc skip_init
// adjust stack
	lea IMAGE_BASE(%rip),%rax
	add %rax,%rsp
	mov %rsp,%gs:tls_tos
// call thread_init
	mov %rdi,%rbx
	mov %rsi,%r12
	mov %rdx,%r13
	mov %r8,%r14
	mov %r9,%r15
	call thread_init
	mov %rbx,%rdi
	mov %r12,%rsi
	mov %r13,%rdx
	mov %r14,%r8
	mov %r15,%r9
skip_init:
// check for panic
	bt $0,panicked(%rip)
	jc reentry_panic
// call into main entry point
	call entry
	mov %rax,%rdx  // RDX = return value
	xor %rdi,%rdi  // RDI = normal exit
exit:
// clear general purpose register state
	// RAX overwritten by ENCLU
	// RBX set later
	// RCX overwritten by ENCLU
	// RDX contains return value
	// RSP set later
	// RBP set later
	// RDI contains exit mode
	xor %rsi,%rsi
	xor %r8,%r8
	xor %r9,%r9
	xor %r10,%r10
	xor %r11,%r11
	// R12 ~ R15 set by sgx_exit
sgx_exit:
// clear extended register state
	mov %rdx, %rcx // save RDX
	mov $-1, %rax
	mov %rax, %rdx
	xrstor xsave_clear(%rip)
	mov %rcx, %rdx // restore RDX
// clear flags
	pushq $0
	popfq
// restore user registers
	mov %gs:tls_user_r12,%r12
	mov %gs:tls_user_r13,%r13
	mov %gs:tls_user_r14,%r14
	mov %gs:tls_user_r15,%r15
	mov %gs:tls_user_retip,%rbx
	mov %gs:tls_user_rsp,%rsp
	mov %gs:tls_user_rbp,%rbp
	fldcw %gs:tls_user_fcw
	ldmxcsr %gs:tls_user_mxcsr
// exit enclave
	mov $0x4,%eax // EEXIT
	enclu
// end sgx_entry

#ifdef DEBUG
.global panic_msg

.global get_debug_panic_buf_ptr
get_debug_panic_buf_ptr:
	mov %gs:tls_debug_panic_buf_ptr,%rax
	ret

usercall_panic_msg:
	.asciz "Invalid usercall#!"
usercall_panic_msg_end:
reentry_panic_msg:
	.asciz "Re-entered panicked enclave!"
reentry_panic_msg_end:
#endif

.global panic_exit
reentry_panic:
#ifdef DEBUG
	lea reentry_panic_msg(%rip),%rdi
	mov $reentry_panic_msg_end-reentry_panic_msg,%esi
	orq $8,%rsp
	jmp panic_msg
#endif
usercall_panic:
#ifdef DEBUG
	lea usercall_panic_msg(%rip),%rdi
	mov $usercall_panic_msg_end-usercall_panic_msg,%esi
	orq $8,%rsp
	jmp panic_msg
#endif
panic_exit:
	movb $1,panicked(%rip)
	xor %rdx,%rdx // RDX cleared
	movq $~0,%rdi // RDI = panic exit
	jmp exit

// This *MUST* be called with 6 parameters, otherwise register information
// might leak!
.global usercall
usercall:
	test %rdi,%rdi
	jle usercall_panic
// save callee-saved state
	push %r15
	push %r14
	push %r13
	push %r12
	push %rbp
	push %rbx
	sub $8, %rsp
	fstcw 4(%rsp)
	stmxcsr (%rsp)
	movq %rsp,%gs:tls_last_rsp
// clear general purpose register state
	// RAX overwritten by ENCLU
	// RBX set by sgx_exit
	// RCX overwritten by ENCLU
	// RDX contains parameter
	// RSP set by sgx_exit
	// RBP set by sgx_exit
	// RDI contains parameter
	// RSI contains parameter
	// R8 contains parameter
	// R9 contains parameter
	xor %r10,%r10
	xor %r11,%r11
	// R12 ~ R15 set by sgx_exit
// extended registers/flags cleared by sgx_exit
// exit
	jmp sgx_exit
usercall_ret:
	movq $0,%gs:tls_last_rsp
// restore callee-saved state
	mov %r11,%rsp
	ldmxcsr (%rsp)
	fldcw 4(%rsp)
	add $8, %rsp
	pop %rbx
	pop %rbp
	pop %r12
	pop %r13
	pop %r14
	pop %r15
// return
	mov %rdx,%rax
	ret

.global get_thread_id
get_thread_id:
	mov %gs:tls_tos,%rax
	ret
