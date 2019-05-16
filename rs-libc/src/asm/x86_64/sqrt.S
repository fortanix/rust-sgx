	.file "sqrt.c"
	.text
..TXTST0:
# -- Begin  sqrt
	.text
       .align    16,0x90
	.globl sqrt
sqrt:
# parameter 1: %xmm0
..B1.1:
	.cfi_startproc
..___tag_value_sqrt.1:
..L2:

        pushq     %rsi
	.cfi_def_cfa_offset 16
..B1.2:
        movq      %xmm0, %xmm2
        xorpd     %xmm1, %xmm1
        sqrtsd    %xmm0, %xmm0
        ucomisd   %xmm1, %xmm2
        jae       ..B1.5
        jp        ..B1.5
        movq      %xmm0, (%rsp)
..B1.3:
        movq      (%rsp), %xmm0
.L_2TAG_PACKET_0.0.2:
..B1.5:
        popq      %rcx
	.cfi_def_cfa_offset 8
        ret       
        .align    16,0x90
	.cfi_endproc
	.type	sqrt,@function
	.size	sqrt,.-sqrt
	.data
# -- End  sqrt
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 1
# End
