# Test switch with shift in indirect operand /w memory load of unsigned data

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!
    mov fp,sp

    adrp x22, .L_jumptable
    add x22,x22, :lo12:.L_jumptable

    cmp w0,#3
    b.hi .L_exit

.jump:
    ldrh w0,[x22,x0, lsl #1]
    adr x1, .L0
    add x0,x1,x0, lsl #2
    br x0

.L0:
    adrp x0, .s_zero
    add x0, x0, :lo12:.s_zero
    b .L_print
.L1:
    adrp x0, .s_one
    add x0, x0, :lo12:.s_one
    b .L_print
.L2:
    adrp x0, .s_two
    add x0, x0, :lo12:.s_two
    b .L_print
.L3:
    adrp x0, .s_three
    add x0, x0, :lo12:.s_three

.L_print:
    bl printf

.L_exit:
    ldp fp,lr,[sp],#16
    mov x0, #0
    ret

.L_exit2:
    ldp fp,lr,[sp],#16
    mov x0, #1
    ret

.L_jumptable:
    .short (.L0-.L0)/4
    .short (.L1-.L0)/4
    .short (.L2-.L0)/4
    .short (.L3-.L0)/4

.section .rodata
.s_zero:
    .ascii "zero\n\0"
.s_one:
    .ascii "one\n\0"
.s_two:
    .ascii "two\n\0"
.s_three:
    .ascii "three\n\0"
