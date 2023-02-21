    .section .rodata
    .align 8
.LC0:
    .string "hello"
    .quad nop.block.size12
    .quad nop.block.size8
    .quad nop.block.size28

	.text

	.globl  foo
	.type	foo, @function
# foo is a never-reaching function that intentionally makes
# the two nop blocks overlap.
foo:
    leaq nop.block.size8(%rip), %rsi
    jmp main
    jmp nop.block.size8.2

nop.block.size12:
    .byte 0x66
    .byte 0x66
    .byte 0x66
    .byte 0x2e
nop.block.size8:
    .byte 0x0f
    .byte 0x1f
    .byte 0x84
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00

	.globl  main
	.type	main, @function
main:
.LFB6:
	pushq	%rbp
	movq	%rsp, %rbp
    leaq     .LC0(%rip), %rdi
    call     puts@PLT
	movl	$0, %eax
	popq	%rbp
	ret

.LFE6:
	.size	main, .-main

nop.block.size28:
    .byte 0x0f
    .byte 0x1f
    .byte 0x84
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x66
    .byte 0x2e
    .byte 0x0f
    .byte 0x1f
    .byte 0x84
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x66
    .byte 0x2e
nop.block.size8.2:
    .byte 0x0f
    .byte 0x1f
    .byte 0x84
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
    .byte 0x00
