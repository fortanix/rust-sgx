	.file "frexpf.c"
	.text
..TXTST0:
# -- Begin  frexpf
	.text
       .align    16,0x90
	.globl frexpf
frexpf:
# parameter 1: %xmm0
# parameter 2: %rdi
..B1.1:
	.cfi_startproc
..___tag_value_frexpf.1:
..L2:

        movd      %xmm0, %edx
        movss     %xmm0, -8(%rsp)
        movl      %edx, %eax
        andl      $2147483647, %eax
        lea       -8388608(%rax), %ecx
        cmpl      $2130706432, %ecx
        jb        ..B1.5
..B1.2:
        decl      %eax
        cmpl      $2139095039, %eax
        jae       ..B1.6
..B1.3:
        movl      %edx, -20(%rsp)
        orl       $1056964608, %edx
        movl      %edx, -24(%rsp)
        andl      $-2147483648, %edx
        orl       $1056964608, %edx
        movl      %edx, -16(%rsp)
        movss     -24(%rsp), %xmm2
        movss     -20(%rsp), %xmm1
        movss     -20(%rsp), %xmm0
        subss     -16(%rsp), %xmm2
        addss     %xmm0, %xmm1
        movd      %xmm2, %eax
        movss     %xmm1, -20(%rsp)
        movl      %eax, %edx
        andl      $-2139095041, %eax
        andl      $2139095040, %edx
        orl       $1056964608, %eax
        shrl      $23, %edx
        movl      %eax, -24(%rsp)
        addl      $-251, %edx
        movl      %edx, (%rdi)
        movss     -24(%rsp), %xmm0
..B1.4:
        ret       
..B1.5:
        andl      $-2139095041, %edx
        shrl      $23, %ecx
        orl       $1056964608, %edx
        movl      %edx, -24(%rsp)
        addl      $-125, %ecx
        movl      %ecx, (%rdi)
        movss     -24(%rsp), %xmm0
        ret       
..B1.6:
        movss     -8(%rsp), %xmm0
        movl      $0, (%rdi)
        addss     %xmm0, %xmm0
        ret       
        .align    16,0x90
	.cfi_endproc
	.type	frexpf,@function
	.size	frexpf,.-frexpf
	.data
# -- End  frexpf
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 1
# End
