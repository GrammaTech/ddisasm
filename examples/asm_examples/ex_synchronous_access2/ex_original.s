	.text
	.globl	main
	.type	main, @function
main:
.LFB41:
	.cfi_startproc
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	pushq	%rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	pushq	%rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	leaq	.LC0(%rip), %rdi
	call	puts@PLT
	leaq	struc_array(%rip), %rbx
	leaq	40(%rbx), %r12
	leaq	.LC1(%rip), %rbp
.L2:
# Three	syncrhonous data accesses
	movsbl	2(%rbx), %ecx
	movswl	(%rbx), %edx
	movsbl	3(%rbx), %r8d
	movq	%rbp, %rsi
	movl	$1, %edi
	movl	$0, %eax
	call	__printf_chk@PLT
	addq	$4, %rbx
	cmpq	%r12, %rbx
	jne	.L2
	movl	$0, %eax
	popq	%rbx
	.cfi_def_cfa_offset 24
	popq	%rbp
	.cfi_def_cfa_offset 16
	popq	%r12
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE41:
	.size	main, .-main

	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"Printing data"
.LC1:
	.string	"%i %c %c \n"

	.globl	struc_array
	.data
	.align 32
	.type	struc_array, @object
	.size	struc_array, 40
struc_array:
	.value	0
	.byte	97
	.byte	98
	.value	0
	.byte	97
	.byte	98
	.value	0
	.byte	97
	.byte	98
	.value	0
	.byte	97
	.byte	98
	.value	16706
	.byte	97
	.byte	98
	.value	16706
	.byte	97
	.byte	98
	.value	16706
	.byte	97
	.byte	98
	.value	16706
	.byte	97
	.byte	98
	.value	16706
	.byte	97
	.byte	98
	.value	0
	.byte	97
	.byte	98
