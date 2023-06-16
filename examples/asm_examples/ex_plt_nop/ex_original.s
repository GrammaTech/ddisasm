.section .plt ,"ax",@progbits
.align 16
	bnd jmpq *puts@GOTPCREL(%rip)
bad_ref:
	nop
	nop
	nop
	nop
	nop
	nop
block:
	bnd jmpq *puts@GOTPCREL(%rip)

.text
.globl	main
.type	main, @function
main:
.LFB6:
	pushq	%rbp
	movq	%rsp, %rbp

	leaq	.LC0(%rip), %rdi
	call	puts@PLT

	movl	$0, %eax
	popq	%rbp
	ret
.size	main, .-main

.section .rodata
.quad bad_ref

.LC0:
    .string "hello"
