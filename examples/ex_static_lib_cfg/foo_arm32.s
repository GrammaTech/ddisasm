	.arch armv7-a
	.eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 2
	.eabi_attribute 34, 1
	.eabi_attribute 18, 4
	.file	"foo.c"
	.text
	.section	.rodata.str1.4,"aMS",%progbits,1
	.align	2
.LC0:
	.ascii	"foo: %d\012\000"
	.text
	.align	1
	.p2align 2,,3
	.global	foo
	.arch armv7-a
	.syntax unified
	.thumb
	.thumb_func
	.fpu vfpv3-d16
	.type	foo, %function
foo:
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	ldr	r1, .L4
	push	{r4, lr}
	mov	r4, r0
	mov	r2, r4
.LPIC0:
	add	r1, pc
	movs	r0, #1
	bl	__printf_chk(PLT)
	mov	r0, r4
	pop	{r4, lr}
	b	bar(PLT)
.L5:
	.align	2
.L4:
	.word	.LC0-(.LPIC0+4)
	.size	foo, .-foo
	.ident	"GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
	.section	.note.GNU-stack,"",%progbits
