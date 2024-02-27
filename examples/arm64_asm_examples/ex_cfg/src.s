	.arch armv8-a
	.text
	.global	f
	.type	f, %function
f:
	stp	x29, x30, [sp, -16]!
	mov	x29, sp
	adrp	x0, .message
	add	x0, x0, :lo12:.message
	bl	puts
	nop
	ldp	x29, x30, [sp], 16
	ret

	.align	2
	.global	main
	.type	main, %function
main:
call_direct:
	stp	x29, x30, [sp, -16]!
	mov	x29, sp
	bl	f
call_direct_external:
	adrp	x0, .message
	add	x0, x0, :lo12:.message
	bl	puts

call_indirect:
	adrp	x0, f_pointer
	add	x0, x0, :lo12:f_pointer
	ldr	x0, [x0]
	blr	x0

call_indirect_external:
	adrp	x0, .message
	add	x0, x0, :lo12:.message
	adrp	x1, puts_pointer
	add	x1, x1, :lo12:puts_pointer
	ldr	x1, [x1]
	blr	x1
final:
	mov	w0, 0
	ldp	x29, x30, [sp], 16
	ret

	.section	.rodata
	.align	3
.message:
	.string	"msg"

	.section	.data.rel.local,"aw"
	.align	3
	.global	f_pointer
	.type	f_pointer, %object
	.size	f_pointer, 8
f_pointer:
	.xword	f

	.global	puts_pointer
	.type	puts_pointer, %object
	.size	puts_pointer, 8
puts_pointer:
	.xword	puts
