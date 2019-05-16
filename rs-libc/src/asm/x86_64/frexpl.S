	.file "frexpl.c"
	.text
..TXTST0:
# -- Begin  frexpl
	.text
       .align    16,0x90
	.globl frexpl
frexpl:
# parameter 1: 32 + %rsp
# parameter 2: %rdi
..B1.1:
	.cfi_startproc
..___tag_value_frexpl.1:
..L2:

        subq      $24, %rsp
	.cfi_def_cfa_offset 32
..B1.2:
        fnstcw    18(%rsp)
..B1.3:
        movzwl    40(%rsp), %edx
        movl      %edx, %eax
        andl      $32767, %eax
        cmpl      $32767, %eax
        je        ..B1.15
..B1.4:
        testl     %eax, %eax
        jne       ..B1.13
..B1.5:
        cmpq      $0, 32(%rsp)
        je        ..B1.12
..B1.6:
        movzwl    18(%rsp), %edx
        movl      %edx, %eax
        andl      $768, %eax
        cmpl      $768, %eax
        je        ..B1.14
..B1.7:
        orl       $-64768, %edx
        movl      $0, (%rdi)
        movw      %dx, 16(%rsp)
..B1.8:
        fldcw     16(%rsp)
..B1.9:
        fldt      32(%rsp)
        lea       _TWO_75(%rip), %rax
        fmull     (%rax)
        fstpt     32(%rsp)
..B1.10:
        fldcw     18(%rsp)
..B1.11:
        movzwl    40(%rsp), %edx
        movl      %edx, %eax
        andl      $-32768, %edx
        andl      $32767, %eax
        orl       $-49154, %edx
        addl      $-16457, %eax
        movw      %dx, 40(%rsp)
        fldt      32(%rsp)
        movl      %eax, (%rdi)
        addq      $24, %rsp
	.cfi_def_cfa_offset 8
        ret       
	.cfi_def_cfa_offset 32
..B1.12:
        fldt      32(%rsp)
        movl      $0, (%rdi)
        addq      $24, %rsp
	.cfi_def_cfa_offset 8
        ret       
	.cfi_def_cfa_offset 32
..B1.13:
        andl      $-32768, %edx
        addl      $-16382, %eax
        orl       $-49154, %edx
        movw      %dx, 40(%rsp)
        fldt      32(%rsp)
        movl      %eax, (%rdi)
        addq      $24, %rsp
	.cfi_def_cfa_offset 8
        ret       
	.cfi_def_cfa_offset 32
..B1.14:
        fldt      32(%rsp)
        lea       _TWO_75(%rip), %rax
        fmull     (%rax)
        fstpt     32(%rsp)
        jmp       ..B1.11
..B1.15:
        movzwl    18(%rsp), %edx
        movl      %edx, %eax
        andl      $768, %eax
        movl      $0, (%rdi)
        cmpl      $768, %eax
        je        ..B1.21
..B1.16:
        orl       $-64768, %edx
        movw      %dx, 16(%rsp)
..B1.17:
        fldcw     16(%rsp)
..B1.18:
        fldt      32(%rsp)
        fstpt     (%rsp)
..B1.19:
        fldcw     18(%rsp)
..B1.20:
        fldt      (%rsp)
        addq      $24, %rsp
	.cfi_def_cfa_offset 8
        ret       
	.cfi_def_cfa_offset 32
..B1.21:
        fldt      32(%rsp)
        fstpt     (%rsp)
        jmp       ..B1.20
        .align    16,0x90
	.cfi_endproc
	.type	frexpl,@function
	.size	frexpl,.-frexpl
	.data
# -- End  frexpl
	.section .rodata, "a"
	.align 4
	.align 4
_TWO_75:
	.long	0
	.long	1151336448
	.long	0
	.long	994050048
	.type	_TWO_75,@object
	.size	_TWO_75,16
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 1
# End
