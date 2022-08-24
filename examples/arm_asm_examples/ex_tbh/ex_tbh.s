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
    tbh [pc, r0]

.jt:
    .hword (.case0 - .jt) / 2
    .hword (.case1 - .jt) / 2
    .hword (.case2 - .jt) / 2
    .hword (.case3 - .jt) / 2

    @ Using nops for each case ensures that the jump table targets must drive
    @ code block boundaries.
.case0:
    nop
.case1:
    @ emit a large code block of nops. This ensures some of the jump table
    @ entries have values that could be misinterpreted as negative if the
    @ entries were considered signed.
    .fill 32768, 2, 0xbf00
.case2:
    nop
.case3:
    nop

.exit:
    mov r0, 0
    pop { pc }
