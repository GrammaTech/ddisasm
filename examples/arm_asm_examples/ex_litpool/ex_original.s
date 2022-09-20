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
	push	{r3, r4, lr}
	sub sp, #32
    adr r0, .L_1
    ldrd r3, r4, [r0]
    strd r3, r4, [sp]
    ldr r0, [sp]
    bl fun
    adr r0, .L_2
    ldm r0, {r3, r4}
    stm sp, {r3, r4}
    ldr r0, [sp]
    bl fun
.thumb
	movs	r3, #0
	mov	r0, r3
    add sp, #32
	pop	{r3, r4, pc}

.align 2
// The following bytes are supposed to be literal pool data accessed by load
// instructions above.
// The bytes are formulated to become a fake code block to compete with the
// data block (literal pool) in code inference.
// If the literal pool references are not correctly detected, this will be
// disassembled as code instead of data.
.L_1:
    .word 0x52c0f64f // movw r2, 0xfdc0
    .word 0x72fff6cf // movt r1, 0xffff
.L_2:
    .word 0xdb0c2a00 // cmp r2, 0; blt
    .word 0x47702001 // movhi r0, 1; bx lr
