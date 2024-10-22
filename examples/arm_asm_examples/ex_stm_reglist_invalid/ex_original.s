# Regression test: `stm r0!, {r0, r1}` is not considered an invalid instruction.
# `stm r1!, {r0, r1, r2}` causes a warning but compiles and it has been
# seen in real binaries

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
    ldr r1, =data
    # this causes a warning "Warning: value stored for r1 is UNKNOWN", but compiles
    # if r1 is later not used it is acceptable
    stm r1!, {r0, r1, r2}
    mov r0, 0
    pop { pc }

.section .data
data:
    .long 0
    .long 1
    .long 2
