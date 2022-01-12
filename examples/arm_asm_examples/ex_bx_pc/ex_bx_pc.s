.syntax unified
.section .text

.thumb
.global	main
.type	main, %function
main:
    bx pc
    nop
.arm
    mov r0, #0
    bx lr
