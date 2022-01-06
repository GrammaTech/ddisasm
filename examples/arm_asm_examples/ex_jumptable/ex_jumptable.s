.syntax unified
.section .text

.global	main
.type	main, %function
.arm

main:
    push { lr }

    mov r0, #0
    cmp r0, #7
    ldrls pc, [pc, r0, LSL2]
    b .exit

.jt:
    .long .case1
    .long .case2
    .long .case3
.split:
    .long .case4
    .long .case5
    .long .case6

.case1:
    nop
.case2:
    nop
.case3:
    nop
.case4:
    nop
.case5:
    nop
.case6:
    nop

.exit:
    mov r0, 0
    pop { pc }

.section .rodata
    @ Ensure the jumptable is split into multiple code block candidates with
    @ address_in_data()
    .long .split
