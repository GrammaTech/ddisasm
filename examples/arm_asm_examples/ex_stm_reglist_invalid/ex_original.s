# Regression test: `stm r0!, {r0, r1}` is not considered an invalid instruction.

.syntax unified
.section .text

.global	main
.type	main, %function
.thumb
.align 4
main:
    push { lr }

    ldr r0, =data
    stm r0!, {r0, r1}
    mov r0, 0
    pop { pc }

.section .data
data:
    .long 0
    .long 1
