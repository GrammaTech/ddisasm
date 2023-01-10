.syntax unified
.section .text

.global	main
.type	main, %function
.thumb
.align 4
main:
    push { lr }
    ands r0, r0, #3
    beq .zero
    tbb [pc, r0]
.jt:
    .byte 0
    .byte (.case1 - .jt) / 2
    .byte (.case2 - .jt) / 2
    .byte (.case3 - .jt) / 2
.case1:
    ldr r0, =.s_one
    b .print
.case2:
    ldr r0, =.s_two
    b .print
.case3:
    ldr r0, =.s_three
    b .print
.zero:
    ldr r0, =.s_zero
    b .print
.print:
    bl printf
    mov r0, #0
    pop { pc }

.section .rodata
.s_zero:
    .string "zero\n"
.s_one:
    .string "one\n"
.s_two:
    .string "two\n"
.s_three:
    .string "three\n"
