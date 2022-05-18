	.arch armv8-a
	.file	"foo.c"
	.text
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align	3
.LC0:
	.string	"foo: %d\n"
	.text
	.align	2
	.p2align 3,,7
	.global	foo
	.type	foo, %function
foo:
.LFB23:
	.cfi_startproc
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	mov	w2, w0
	adrp	x1, .LC0
	mov	x29, sp
	add	x1, x1, :lo12:.LC0
	str	x19, [sp, 16]
	.cfi_offset 19, -16
	mov	w19, w0
	mov	w0, 1
	bl	__printf_chk
	mov	w0, w19
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_def_cfa_offset 0
	b	bar
	.cfi_endproc
.LFE23:
	.size	foo, .-foo
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",@progbits
