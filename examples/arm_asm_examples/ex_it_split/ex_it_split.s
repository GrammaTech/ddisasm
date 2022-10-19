.syntax unified

#===================================
.section .text
#===================================

.thumb
.global	main
.type	main, %function
main:
    push { lr }
    cmp r0, #10
    itt eq
test_ptr:
    moveq r0, #1
    bxeq lr

    cmp r0, #7
    beq .L1
    blx foo

    ldr r0, .L2
    blx printf
.L1:
    mov r0, #0
    pop { pc }

.arm
.global	foo
.type	foo, %function
foo:
    mov r0, #0
    bx lr

.L2:
    .long print_format

#===================================
.section .rodata ,"a",%progbits
#===================================
.align 2
// Reference the middle of the IT block, which must not be split into two blocks.
    .word test_ptr+1
print_format:
    .string "arm32 cfg test\n"
