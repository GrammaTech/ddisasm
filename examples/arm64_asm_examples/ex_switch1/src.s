# Test switch with shift in indirect operand

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!
    mov fp,sp

    mov w0, #2

    adrp x1, .L_jumptable
    add x1,x1, :lo12:.L_jumptable
    ldr w0,[x1,w0,uxtw #2]
    adr x1, .L0
    add x0,x1,w0, sxtw #2
    br x0

.L0:
    adrp x0, .s_zero
    add x0, x0, :lo12:.s_zero
    b .L_exit
.L1:
    adrp x0, .s_one
    add x0, x0, :lo12:.s_one
    b .L_exit
.L2:
    adrp x0, .s_two
    add x0, x0, :lo12:.s_two
    b .L_exit
.L3:
    adrp x0, .s_three
    add x0, x0, :lo12:.s_three

.L_print:
    bl printf

.L_exit:
    ldp fp,lr,[sp],#16
    mov x0, #0
    ret

.L_jumptable:
      .long (.L0-.L0)/4
      .long (.L1-.L0)/4
      .long (.L2-.L0)/4
      .long (.L3-.L0)/4

.section .rodata
.s_zero:
    .ascii "zero\n\0"
.s_one:
    .ascii "one\n\0"
.s_two:
    .ascii "two\n\0"
.s_three:
    .ascii "three\n\0"
