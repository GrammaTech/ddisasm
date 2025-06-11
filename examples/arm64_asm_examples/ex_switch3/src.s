# Test switch with a backward jump and single-byte data.

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!
    mov fp,sp
    b .next

.L3:
    # The jump table must jump backwards to here.
    add x0, x25, :lo12:.s_three
    b .L_print

.next:
    mov w0, #3
    cmp w0, #3
    b.hi .L_exit

.jump:
    # split the loads across the jumptable to ensure that they are not
    # correctly symbolized unless the jumptable is correct.
    adrp x22, .s_zero
    adrp x23, .s_one
    adrp x24, .s_two
    adrp x25, .s_three

    adrp x1, .L_jumptable
    add x1,x1, :lo12:.L_jumptable
    ldrb w0,[x1,w0,uxtw]
    adr x1, .L0
    add x0,x1,w0, sxtb #2
    br x0

.L0:
    add x0, x22, :lo12:.s_zero
    b .L_print
.L1:
    add x0, x23, :lo12:.s_one
    b .L_print
.L2:
    add x0, x24, :lo12:.s_two
    b .L_print

.L_print:
    bl printf

.L_exit:
    ldp fp,lr,[sp],#16
    mov x0, #0
    ret

.section .rodata
.L_jumptable:
    .byte (.L0-.L0)/4
    .byte (.L1-.L0)/4
    .byte (.L2-.L0)/4
    .byte (.L3-.L0)/4

.s_zero:
    .ascii "zero\n\0"
.s_one:
    .ascii "one\n\0"
.s_two:
    .ascii "two\n\0"
.s_three:
    .ascii "three\n\0"
