.syntax unified
.section .text

.global	main
.type	main, %function
.thumb
.align 4
main:
    push { lr }
    mov r0, 2
    cmp r0, #3
    bhi .exit
    tbb [pc, r0]

.jt:
    .byte (.case0 - .jt) / 2
    .byte (.case1 - .jt) / 2
.split:
    .byte (.case2 - .jt) / 2
    .byte (.case3 - .jt) / 2

    @ Using nops for each case ensures that the jump table targets must drive
    @ code block boundaries.
.case0:
    nop
.case1:
    nop
.case2:
    nop
.case3:
    nop

.exit:
    mov r0, 0
    pop { pc }

.section .rodata
    @ Ensure the jumptable is split into multiple code block candidates with
    @ address_in_data()
    .long .split
