	.file	"ex.c"
	.text
	.section	.rodata
	.align 8
.LC0:
	.string	"function reached through pointer"
	.text
	.globl	msg
	.type	msg, @function
msg:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	leaq	.LC0(%rip), %rdi
	call	puts@PLT
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	msg, .-msg
	.globl	array
	.data
	.align 16
	.type	array, @object
	.size	array, 16
array:
	.value	1
	.value	2
	.value	3
	.value	4
	.value	5
	.value	6
	.value	7
	.value	8
	.globl	msg_pointer
	.align 8
	.type	msg_pointer, @object
	.size	msg_pointer, 8
msg_pointer:
	.quad	msg
	.section	.rodata
.LC1:
	.string	"Printing data"
.LC2:
	.string	"%i  \n"
	.text
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
	subq	$16, %rsp
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
	movl	$0, -12(%rbp)
	jmp	.L3
.L4:
	movl	-12(%rbp), %eax
	cltq
	leaq	(%rax,%rax), %rdx
	leaq	array(%rip), %rax
	movzwl	(%rdx,%rax), %eax
	cwtl
	movl	%eax, %esi
	leaq	.LC2(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	addl	$1, -12(%rbp)
.L3:
	cmpl	$7, -12(%rbp)
	jle	.L4
	leaq	array(%rip), %rax
	# access "array" with size 4
	movl	(%rax), %eax
	movl	%eax, %esi
	leaq	.LC2(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	# compute pointer to function pointer
	# without directly referencing it
	leaq	array(%rip), %rax
	movq	%rax, -8(%rbp)
	addq	$16, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	(%rax), %rdx
	movl	$0, %eax
	call	*%rdx
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
