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

    # TODO: SYS (at_op)
    # Currently decoded incorrectly using capstone 5.x (next).
    # AT S12E0R, x0

    ldp fp,lr,[sp],#16
    ret
