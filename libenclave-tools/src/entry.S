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
	.size \name , \size
	\name :
		.org .+\size
.endm

.section absolute
.global IMAGE_BASE
IMAGE_BASE:

.section .rodata
	globvar HEAP_BASE 8
	globvar HEAP_SIZE 8
	globvar RELA 8
	globvar RELACOUNT 8
	globvar ENCLAVE_SIZE 8

.data
#ifdef DEBUG
	globvar DEBUG_PANIC_BUF_PTR 8
#endif
init_once:
	.byte 0
panicked:
	.byte 0

// stack section

// TLS section
#define tls_tos        0x00 // initialized by loader to *offset* from image base to TOS
#define tls_last_rsp   0x08 // initialized by loader to 0
#define tls_user_rsp   0x10
#define tls_user_retip 0x18
#define tls_user_rbp   0x20
#define tls_user_r12   0x28
#define tls_user_r13   0x30
#define tls_user_r14   0x38
#define tls_user_r15   0x40

/*************************
 ******* sgx_entry *******
 *************************
 * TCS.NSSA should be 1 (except when compiled for debug).
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
 *      A later normal exit will return to the point indicated by the original
 *      call.
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
 *
 * >>debug<<
 *   When compiled for debug, use TCS.NSSA=2 (or more). Upon AEX, enter again
 *   to call the function debug_copy(dst: *mut u8, src: *const u8). This will
 *   call memcpy(dst,src,0x1000). Use the standard System V calling convention,
 *   except ENCLU registers (EAX, RBX, RCX) are also clobbered.
 *************************/

.text
.global sgx_entry
.type sgx_entry,function
sgx_entry:
#ifdef DEBUG
	test %eax,%eax // TCS.CSSA
	jz no_debug
	mov %rsp,%gs:tls_user_rsp
	mov %rcx,%gs:tls_user_retip
	call debug_copy
	jmp sgx_exit
no_debug:
#endif
// check if returning from usercall
	mov %gs:tls_last_rsp,%r11
	test %r11,%r11
	jnz usercall_ret
#ifdef DEBUG
	mov %r10,DEBUG_PANIC_BUF_PTR(%rip)
#endif
// save registers and setup stack
	mov %rcx,%gs:tls_user_retip
	mov %rsp,%gs:tls_user_rsp
	mov %rbp,%gs:tls_user_rbp
	mov %r12,%gs:tls_user_r12
	mov %r13,%gs:tls_user_r13
	mov %r14,%gs:tls_user_r14
	mov %r15,%gs:tls_user_r15
	mov %gs:tls_tos,%rsp
// check for panic
	bt $0,panicked(%rip)
	jc panic_exit
// check for init
	bt $0,init_once(%rip)
	jc skip_init
	movb $1,init_once(%rip)
// adjust stack -- NOTE: this needs to happen for every thread, not just once...
	lea IMAGE_BASE(%rip),%rax
	add %rax,%rsp
	mov %rsp,%gs:tls_tos
// call init
	mov %rdi,%rbx
	mov %rsi,%r12
	mov %rdx,%r13
	mov %r8,%r14
	mov %r9,%r15
	call init
	mov %rbx,%rdi
	mov %r12,%rsi
	mov %r13,%rdx
	mov %r14,%r8
	mov %r15,%r9
skip_init:
	call entry
	mov %rax,%rdx  // RDX = return value
	xor %rdi,%rdi  // RDI = normal exit
exit:
	// RAX overwritten by ENCLU
	// RBX set later
	// RCX overwritten by ENCLU
	// RDX contains return value
	// RSP set later
	mov %gs:tls_user_rbp,%rbp
	// RDI contains exit mode
	xor %rsi,%rsi
	xor %r8,%r8
	xor %r9,%r9
	xor %r10,%r10
	xor %r11,%r11
	mov %gs:tls_user_r12,%r12
	mov %gs:tls_user_r13,%r13
	mov %gs:tls_user_r14,%r14
	mov %gs:tls_user_r15,%r15
sgx_exit:
	mov %gs:tls_user_retip,%rbx
	mov %gs:tls_user_rsp,%rsp
	pushq $0
	popfq
	mov $0x4,%eax // EEXIT
	enclu
// end sgx_entry

#ifdef DEBUG
.global panic_msg
usercall_panic_msg:
	.asciz "Invalid usercall#!"
usercall_panic_msg_end:
#endif

.global panic_exit
usercall_panic:
#ifdef DEBUG
	lea usercall_panic_msg(%rip),%rdi
	mov usercall_panic_msg_end-usercall_panic_msg,%esi
	call panic_msg
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
	push %r15
	push %r14
	push %r13
	push %r12
	push %rbp
	push %rbx
	// RAX overwritten by ENCLU
	// RBX set later
	// RCX overwritten by ENCLU
	// RDX contains parameter
	// RSP set later
	mov %gs:tls_user_rbp,%rbp
	// RDI contains parameter
	// RSI contains parameter
	// R8 contains parameter
	// R9 contains parameter
	xor %r10,%r10
	xor %r11,%r11
	mov %gs:tls_user_r12,%r12
	mov %gs:tls_user_r13,%r13
	mov %gs:tls_user_r14,%r14
	mov %gs:tls_user_r15,%r15
	movq %rsp,%gs:tls_last_rsp
	jmp sgx_exit
usercall_ret:
	mov %r11,%rsp
	movq $0,%gs:tls_last_rsp
	mov %rdx,%rax
	pop %rbx
	pop %rbp
	pop %r12
	pop %r13
	pop %r14
	pop %r15
	ret
