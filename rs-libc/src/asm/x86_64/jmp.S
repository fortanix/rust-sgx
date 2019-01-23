/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// To be used with a jmp_buf of at least 70 bytes.
//
// Interesting discussion on what should be saved in setjmp/longjmp:
//   https://lists.freebsd.org/pipermail/freebsd-amd64/2008-June/011284.html
// TL;DR: Almost all implementation are broken. What we do is correct.

	.global setjmp, _setjmp
	.type setjmp,@function
	.equ _setjmp, setjmp
setjmp:
	movq 0(%rsp), %rax
	movq %rax, 0x00(%rdi)
	movq %rbx, 0x08(%rdi)
	movq %rsp, 0x10(%rdi)
	movq %rbp, 0x18(%rdi)
	movq %r12, 0x20(%rdi)
	movq %r13, 0x28(%rdi)
	movq %r14, 0x30(%rdi)
	movq %r15, 0x38(%rdi)
	stmxcsr 0x40(%rdi)
	fstcw 0x44(%rdi)
	xorq %rax, %rax
	ret
1:
	.size setjmp, 1b-setjmp

	.global longjmp, _longjmp
	.type longjmp,@function
	.equ _longjmp, longjmp
longjmp:
	movq 0x00(%rdi), %rax
	movq 0x08(%rdi), %rbx
	movq 0x10(%rdi), %rsp
	movq 0x18(%rdi), %rbp
	movq 0x20(%rdi), %r12
	movq 0x28(%rdi), %r13
	movq 0x30(%rdi), %r14
	movq 0x38(%rdi), %r15
	ldmxcsr 0x40(%rdi)
	fldcw 0x44(%rdi)
	movq %rax, 0(%rsp)
	test %rsi, %rsi
	movl $1, %eax
	cmovnz %rsi, %rax
	ret
2:
	.size longjmp, 2b-longjmp
