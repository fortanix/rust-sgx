	.file "fabs.c"
	.text
..TXTST0:
# -- Begin  fabs
	.text
       .align    16,0x90
	.globl fabs
fabs:
# parameter 1: %xmm0
..B1.1:
	.cfi_startproc
..___tag_value_fabs.1:
..L2:

..B1.2:
        movq      MASK(%rip), %xmm1
        movq      ONE(%rip), %xmm2
        andpd     %xmm1, %xmm0
        mulsd     %xmm2, %xmm0
        ret       
..B1.3:
        .align    16,0x90
	.cfi_endproc
	.type	fabs,@function
	.size	fabs,.-fabs
	.data
# -- End  fabs
	.section .rodata, "a"
	.align 16
	.align 16
MASK:
	.long	4294967295
	.long	2147483647
	.type	MASK,@object
	.size	MASK,8
	.space 8, 0x00 	# pad
	.align 16
ONE:
	.long	0
	.long	1072693248
	.type	ONE,@object
	.size	ONE,8
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 1
# End
