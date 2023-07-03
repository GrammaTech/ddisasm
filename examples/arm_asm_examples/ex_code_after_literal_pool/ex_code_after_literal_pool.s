.syntax unified
.section .text

.global	main
.type	main, %function
main:
    push { lr }
    ldr r0, .L2
    blx printf
    mov r0, #0
    pop { pc }
.L2:
    .long str

# here, we have some code that nothing references, and occurs after a literal
# pool. We want to ensure it is still considered code.

    mov r1, r0
    ldr r0, [r1, #10]
    bx lr

#===================================
.section .rodata ,"a",%progbits
#===================================

.align 2
str:
    .string "hello world\n"
