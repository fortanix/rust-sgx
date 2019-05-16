	.file "ldexpf.c"
	.text
..TXTST0:
# -- Begin  ldexpf
	.text
       .align    16,0x90
	.globl ldexpf
ldexpf:
# parameter 1: %xmm0
# parameter 2: %edi
..B1.1:
	.cfi_startproc
..___tag_value_ldexpf.1:
..L2:

        movl      %edi, %r8d
        movss     %xmm0, -8(%rsp)
        movzwl    -6(%rsp), %eax
        movl      %eax, %esi
        andl      $32640, %esi
        shrl      $7, %esi
        cmpl      $255, %esi
        je        ..B1.9
..B1.2:
        xorb      %dil, %dil
        testl     %esi, %esi
        jne       ..B1.5
..B1.3:
        testl     $8388607, -8(%rsp)
        je        ..B1.9
..B1.4:
        movss     -8(%rsp), %xmm0
        movb      $1, %dil
        mulss     .L_2il0floatpacket.0(%rip), %xmm0
        movss     %xmm0, -8(%rsp)
        movzwl    -6(%rsp), %eax
        movl      %eax, %esi
        andl      $32640, %esi
        shrl      $7, %esi
        addl      $-25, %esi
..B1.5:
        movl      $65536, %edx
        cmpl      $65536, %r8d
        cmovg     %edx, %r8d
        movl      $-65536, %ecx
        cmpl      $-65536, %r8d
        cmovle    %ecx, %r8d
        lea       (%rsi,%r8), %edx
        testl     %edx, %edx
        jle       ..B1.11
..B1.6:
        cmpl      $255, %edx
        jge       ..B1.10
..B1.7:
        movzbl    %dl, %edx
        andl      $-32641, %eax
        shll      $7, %edx
        orl       %edx, %eax
        movw      %ax, -6(%rsp)
        movss     -8(%rsp), %xmm0
..B1.8:
        ret       
..B1.9:
        movss     -8(%rsp), %xmm0
        ret       
..B1.10:
        movb      -5(%rsp), %al
        lea       _large_value_32(%rip), %rdx
        andb      $-128, %al
        shrb      $7, %al
        movzbl    %al, %ecx
        movss     (%rdx,%rcx,4), %xmm0
        mulss     .L_2il0floatpacket.1(%rip), %xmm0
        ret       
..B1.11:
        cmpl      $-23, %edx
        jl        ..B1.15
..B1.12:
        andl      $-32641, %eax
        lea       25(%rsi,%r8), %edx
        movzbl    %dl, %edx
        shll      $7, %edx
        orl       %edx, %eax
        movw      %ax, -6(%rsp)
        testb     %dil, %dil
        movss     -8(%rsp), %xmm0
        mulss     .L_2il0floatpacket.3(%rip), %xmm0
        je        ..B1.14
..B1.13:
        testl     %r8d, %r8d
        jl        ..B1.8
..B1.14:
        ret       
..B1.15:
        movb      -5(%rsp), %al
        lea       _small_value_32(%rip), %rdx
        andb      $-128, %al
        shrb      $7, %al
        movzbl    %al, %ecx
        movss     (%rdx,%rcx,4), %xmm0
        mulss     .L_2il0floatpacket.2(%rip), %xmm0
        ret       
        .align    16,0x90
	.cfi_endproc
	.type	ldexpf,@function
	.size	ldexpf,.-ldexpf
	.data
# -- End  ldexpf
	.section .rodata, "a"
	.align 4
	.align 4
.L_2il0floatpacket.0:
	.long	0x4c000000
	.type	.L_2il0floatpacket.0,@object
	.size	.L_2il0floatpacket.0,4
	.align 4
.L_2il0floatpacket.1:
	.long	0x71800000
	.type	.L_2il0floatpacket.1,@object
	.size	.L_2il0floatpacket.1,4
	.align 4
.L_2il0floatpacket.2:
	.long	0x0d800000
	.type	.L_2il0floatpacket.2,@object
	.size	.L_2il0floatpacket.2,4
	.align 4
.L_2il0floatpacket.3:
	.long	0x33000000
	.type	.L_2il0floatpacket.3,@object
	.size	.L_2il0floatpacket.3,4
	.align 4
_large_value_32:
	.long	1904214016
	.long	4051697664
	.type	_large_value_32,@object
	.size	_large_value_32,8
	.align 4
_small_value_32:
	.long	226492416
	.long	2373976064
	.type	_small_value_32,@object
	.size	_small_value_32,8
	.data
	.section .note.GNU-stack, ""
// -- Begin DWARF2 SEGMENT .eh_frame
	.section .eh_frame,"a",@progbits
.eh_frame_seg:
	.align 1
# End
