	.arch armv7-a

	.section	.rodata
	.align	2
print_format:
    .string "%d\n"

	.text
	.align	2
.thumb
fun:
    push { r1, lr }
    mov     r1, r0
    ldr     r0, .L_3
    bl printf(PLT)
.thumb
    mov r0, #0
    pop { r1, pc }
    .align 2
.L_3:
    .word print_format

	.align	2
	.global	main
	.syntax unified
	.thumb
	.thumb_func
	.type	main, %function
.thumb
main:
	push	{r3, lr}
	sub sp, #32
    adr r0, .L_1
    vld2.32 {d16,d17}, [r0 :128]
    vst2.32 {d16,d17}, [sp]
    ldr r0, [sp, #6]
    bl fun
    ldr r0, [sp, #10]
    bl fun
.thumb
	movs	r3, #0
	mov	r0, r3
    add sp, #32
	pop	{r3, pc}

.align 2
// The following 16 bytes are supposed to be literal pool data accessed by the
// vld2.32 above.
// The bytes are formulated to become a fake code block to compete with the
// data block (literal pool) in code inference.
// If the literal pool reference in the vld2.32 is not correctly detected, this
// will be disassembled as code instead of data.
.L_1:
    .word 0x52c0f64f // movw r2, 0xfdc0
    .word 0x72fff6cf // movt r1, 0xffff
    .word 0xdb0c2a00 // cmp r2, 0; blt
    .word 0x47702001 // movhi r0, 1; bx lr
