# Test strange operand types
.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!
    mov fp,sp

    # SYS
    mrs x0, tpidr_el0
    msr tpidr_el0, x0

    # PSTATE
    msr DAIFSet, #10

    # SYS (at_op)
    at s12e0r, x0
    dc cvau, x2
    ic ivau, x0

    ldp fp,lr,[sp],#16
    ret
