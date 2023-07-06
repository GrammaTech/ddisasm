	.text
	.intel_syntax noprefix
	.file	"ex.c"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	push	rbx
	.cfi_def_cfa_offset 16
	.cfi_offset rbx, -16
	mov	edi, offset .L.str
	mov	esi, 7
	xor	eax, eax
	call	printf
	mov	ebx, 1408
	.p2align	4, 0x90
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
	mov	rsi, qword ptr [rbx + state-88]
	mov	edi, offset .L.str.1
	xor	eax, eax
	call	printf
	add	rbx, -88
	jne	.LBB0_1
# %bb.2:
	xor	eax, eax
	pop	rbx
	ret
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.type	state,@object           # @state
	.data
	.globl	state
	.p2align	4
state:
	.quad	0                       # 0x0
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	1                       # 0x1
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	2                       # 0x2
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	3                       # 0x3
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	4                       # 0x4
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	5                       # 0x5
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	6                       # 0x6
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	7                       # 0x7
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	8                       # 0x8
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	9                       # 0x9
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	10                      # 0xa
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	11                      # 0xb
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	12                      # 0xc
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	13                      # 0xd
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	14                      # 0xe
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.quad	15                      # 0xf
	.quad	1                       # 0x1
	.quad	2                       # 0x2
	.quad	3                       # 0x3
	.quad	4                       # 0x4
	.quad	5                       # 0x5
	.quad	6                       # 0x6
	.quad	7                       # 0x7
	.quad	8                       # 0x8
	.quad	9                       # 0x9
	.quad	10                      # 0xa
	.size	state, 1408

	.type	.L.str,@object          # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%i \n"
	.size	.L.str, 5

	.type	.L.str.1,@object        # @.str.1
.L.str.1:
	.asciz	"%lu \n"
	.size	.L.str.1, 6


	.ident	"clang version 6.0.0-1ubuntu2 (tags/RELEASE_600/final)"
	.section	".note.GNU-stack","",@progbits
