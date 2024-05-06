.syntax unified
.section .text

.thumb
.global ZERO_OBJECT
.type ZERO_OBJECT, %object
.size ZERO_OBJECT, 0
ZERO_OBJECT:

.global	main
.type	main, %function
main:
    mov r0, #0
    bx lr
