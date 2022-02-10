# Test special conditional branch operations (tbz, tbnz, cbz, cbnz)

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!
    mov fp,sp

    mov x19, #8
.loop:
    cbz x19, .zero
    cbnz x19, .test
    b .exit

.zero:
    adrp x0, .fmt_zero
    add x0, x0, :lo12:.fmt_zero
    b .print

.test:
    tbz x19, #0, .even
    tbnz x19, #0, .odd
    b .exit

.odd:
    adrp x0, .fmt_odd
    add x0, x0, :lo12:.fmt_odd
    b .print
.even:
    adrp x0, .fmt_even
    add x0, x0, :lo12:.fmt_even

.print:
    mov x1, x19
    bl printf

    sub x19, x19, #1
    cbnz x19, .loop

    ldp fp,lr,[sp],#16
    mov x0, #0
    ret

.exit:
    ldp fp,lr,[sp],#16
    mov x0, #1
    ret

.section .rodata
.fmt_zero:
    .ascii "%d: zero\n\0"
.fmt_odd:
    .ascii "%d: odd\n\0"
.fmt_even:
    .ascii "%d: even\n\0"
