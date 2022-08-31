	.arch armv7-a

	.section	.rodata
	.align	2
.LC0:
	.ascii	"!!!Hello World!!!\000"
.LC1:
	.ascii	"!!!This is a test!!!\000"
print_format:
    .string "%d\n"

	.text
	.align	2
.thumb
fun:
    push { r1, lr }
    mov     r1, r0
    ldr     r0, .L_1
    bl printf(PLT)
.thumb
    mov r0, #0
    pop { r1, pc }
    .align 2
.L_1:
    .word print_format

	.align	2
	.global	main
	.syntax unified
	.thumb
	.thumb_func
	.type	main, %function
.thumb
main:
	push	{r7, lr}
	add	r7, sp, #0
    # (A): There is no corresponding movt to this: it should not be symbolized.
    movw    r0, #:lower16:.LC1
    bl  fun
.thumb
    # (B) This should be a pair with (C): distance 1
	movw	r0, #:lower16:.LC0
    # (C) This cannot be a pair with (A)
	movt	r0, #:upper16:.LC0
	bl	puts(PLT)
    # (D)
    movw    r1, #:lower16:.LC1
    movw    r0, #7
    bl  fun
    # (E) This should be a pair with (D): distance 3
	movt	r1, #:upper16:.LC1
    mov     r0, r1
    bl  puts(PLT)
.thumb
	movs	r3, #0
	mov	r0, r3
	pop	{r7, pc}
