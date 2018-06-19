	.file	"ex.c"
	.intel_syntax noprefix
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"%i \n"
.LC1:
	.string	"%lu \n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB27:
	.cfi_startproc
	push	r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	push	rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	push	rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	mov	edx, 7
	lea	rsi, .LC0[rip]
	mov	edi, 1
	mov	eax, 0
	call	__printf_chk@PLT
	lea	rbx, state[rip+1320]
	lea	r12, state[rip-88]
	lea	rbp, .LC1[rip]
.L2:
	mov	rdx, QWORD PTR [rbx]
	mov	rsi, rbp
	mov	edi, 1
	mov	eax, 0
	call	__printf_chk@PLT
	sub	rbx, 88
	cmp	rbx, r12
	jne	.L2
	mov	eax, 0
	pop	rbx
	.cfi_def_cfa_offset 24
	pop	rbp
	.cfi_def_cfa_offset 16
	pop	r12
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE27:
	.size	main, .-main
	.globl	state
	.data
	.align 32
	.type	state, @object
	.size	state, 1408
state:
	.quad	0
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	1
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	2
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	3
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	4
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	5
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	6
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	7
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	8
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	9
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	10
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	11
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	12
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	13
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	14
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.quad	15
	.quad	1
	.quad	2
	.quad	3
	.quad	4
	.quad	5
	.quad	6
	.quad	7
	.quad	8
	.quad	9
	.quad	10
	.ident	"GCC: (Ubuntu 5.5.0-12ubuntu1) 5.5.0 20171010"
	.section	.note.GNU-stack,"",@progbits
