.syntax unified
.section .text

.global	main
.type	main, %function
.arm
.align 4
main:
    push { lr }
    cmp r0, #3
    bhi .exit

    mov r5, r0
    ldr ip, [pc, r5, LSL 2]
    add pc, pc, ip
    bkpt #0
.L0:
    .long .case0 - .L0
    .long .case1 - .L0
    .long .case2 - .L0
    .long .case3 - .L0

.case0:
    ldr r0, .L1
    b .print
.case1:
    ldr r0, .L2
    b .print
.case2:
    ldr r0, .L3
    b .print
.case3:
    ldr r0, .L4
    b .print

.print:
    add r0, pc, r0
    bl printf

.exit:
    mov r0, 0
    pop { pc }

.L1:
    .long str_one - (.print + 8)
.L2:
    .long str_two - (.print + 8)
.L3:
    .long str_three - (.print + 8)
.L4:
    .long str_four - (.print + 8)

.section .rodata

str_one:
    .string "one\n"
str_two:
    .string "two\n"
str_three:
    .string "three\n"
str_four:
    .string "four\n"
