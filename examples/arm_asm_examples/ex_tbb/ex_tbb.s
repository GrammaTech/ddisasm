.syntax unified
.section .text

.global	main
.type	main, %function
.thumb
.align 4
main:
    push { lr }

    ldr r0, =print_format
    mov r3, 2

    cmp r3, #3
    bhi .exit

    tbb [pc, r3]

.jt:
    .byte (.case0 - .jt) / 2
    .byte (.case1 - .jt) / 2
    .byte (.case2 - .jt) / 2
    .byte (.case3 - .jt) / 2

.case0:
    mov r1, 4
    b .print
.case1:
    mov r1, 3
    b .print
.case2:
    mov r1, 2
    b .print
.case3:
    mov r1, 1
    b .print

.print:
    bl printf
.exit:
    mov r0, 0
    pop { pc }

.section .rodata
print_format:
    .ascii "%x\n\0"
