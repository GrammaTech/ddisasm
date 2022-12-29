.syntax unified

#===================================
.section .text
#===================================

.arm
.global	main
.type	main, %function
main:
    push { lr }

    cmp r0, #3
    bge .fail

    lsl r0, r0, #2
    ldr r1, .offset
    add r1, r1, r0

.ref:
    ldr r1, [pc, r1]
    ldr r0, .L2
    blx printf
    mov r0, #0
    pop { pc }

.fail:
    mov r0, #1
    pop { pc }

.L2:
    .long print_format

.messages:
    .long .one
    .long .two
    .long .three

.offset:
    .long .messages - (.ref + 8)

#===================================
.section .rodata ,"a",%progbits
#===================================
print_format:
    .string "argument count: %s\n"

.one:
    .string "one"

.two:
    .string "two"

.three:
    .string "three"
