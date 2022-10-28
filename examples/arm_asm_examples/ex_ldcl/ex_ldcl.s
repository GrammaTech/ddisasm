.syntax unified
.section .text

.global	main
.type	main, %function
main:
    push {lr}
    ldcl p1, c0, [r0], #8
    pop {pc}
