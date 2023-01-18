.syntax unified
.section .text
# Unreferenced Thumb code at the start of the section
.thumb
    mov r0, #0
    mov pc, lr

.align 2
.arm
.global _start
_start:
    blx main
    bl exit

.global	main
.type	main, %function
.thumb
.align 2
main:
    push { lr }
    mov r0, #0
    pop { pc }
