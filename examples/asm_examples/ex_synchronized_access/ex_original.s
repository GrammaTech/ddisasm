	.file	"ex.c"
	.text
	# We should detect a synchronized access to
	# this data structure and therefore do not split it
	# into two.
	.comm	ga,80,32
	.section	.rodata
.LC0:
	.string	"%d %d\n"
	.text
	.globl	bar
	.type	bar, @function
bar:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	$0, -12(%rbp)
	jmp	.L2
.L3:
	movl	-12(%rbp), %eax
	cltq
	leaq	0(,%rax,8), %rdx
	leaq	ga(%rip), %rax
	movl	$1, (%rdx,%rax)
	movl	-12(%rbp), %eax
	cltq
	leaq	0(,%rax,8), %rdx
	leaq	4+ga(%rip), %rax
	movb	$2, (%rdx,%rax)
	addl	$1, -12(%rbp)
.L2:
	cmpl	$9, -12(%rbp)
	jle	.L3
	movq	$0, -8(%rbp)
	jmp	.L4
.L5:
	movq	-8(%rbp), %rax
	leaq	0(,%rax,8), %rdx
	leaq	4+ga(%rip), %rax
	movzbl	(%rdx,%rax), %eax
	movsbl	%al, %edx
	movq	-8(%rbp), %rax
	leaq	0(,%rax,8), %rcx
	leaq	ga(%rip), %rax
	movl	(%rcx,%rax), %eax
	movl	%eax, %esi
	leaq	.LC0(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addq	$1, -8(%rbp)
.L4:
	cmpq	$9, -8(%rbp)
	jbe	.L5
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	bar, .-bar
	.globl	main
	.type	main, @function
main:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %eax
	call	bar
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
