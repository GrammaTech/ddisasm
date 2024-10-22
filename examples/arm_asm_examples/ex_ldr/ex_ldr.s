.syntax unified
.section .text
.arm

.global	main
.type	main, %function
main:
    push {lr}

    @ To test that instructions are marked as invalid, we have a series of data
    @ mixed with code, where conditional branch instructions jump over the data.
    @ This results in may-fallthrough into the data, encouraging ddisasm to
    @ disassemble as code if possible.
    @ Each data block is only a single instruction, ensuring propagate-to-
    @ invalid rules don't rule it as data.
    @ GNU as will refuse to assemble most of these invalid instructions, so we
    @ to use the byte encoding of the instruction as a data value.

    mov r0, #2
    cmp r0, #1
    bhi .BHI1

.INVALID0:
    @ invalid: ldrd r1, r2, [r0], #4
    .long 0xe0c010d4

.BHI1:
    cmp r0, #1
    bhi .BHI2

.INVALID1:
    @ invalid: ldrd r1, r2, [r0], r3
    .long 0xe08010d3

.BHI2:
    cmp r0, #1
    bhi .BHI3

.INVALID2:
    @ invalid: ldrd lr, pc, [r0], #4
    .long 0xe0c0e0d4

.BHI3:
    cmp r0, #1
    bhi .BHI4

.INVALID3:
    @ invalid: ldrd lr, pc, [r0], r2
    .long 0xe080e0d2

.BHI4:
    cmp r0, #1
    bhi .BHI5

.INVALID4:
    @ invalid: ldr r0, [r0, r1]!
    .long 0xe7b00001

.BHI5:
    cmp r0, #1
    bhi .BHI6

.INVALID5:
    @ invalid: ldr r0, [r0, #4]!
    .long 0xe5b00004

.BHI6:
    cmp r0, #1
    bhi .BHI7

.INVALID6:
    @ invalid: ldr r0, [r0], r1
    .long 0xe6900001

.BHI7:
    cmp r0, #1
    bhi .BHI8

.INVALID7:
    @ invalid: ldr r0, [r0], #4
    .long 0xe4900004

.BHI8:
    cmp r0, #1
    bhi .BHI9

.INVALID8:
    @ invalid: ldrd r0, r1, [r1, r2]!
    .long 0xe1a100d2

.BHI9:
    cmp r0, #1
    bhi .BHI10

.INVALID9:
    @ invalid: ldrd r0, r1, [r1, #4]!
    .long 0xe1e100d4

.BHI10:
    cmp r0, #1
    bhi .BHI11

.INVALID10:
    @ invalid: ldrd r0, r1, [r1], r2
    .long 0xe08100d2

.BHI11:
    cmp r0, #1
    bhi .BHI12

.INVALID11:
    @ invalid: ldrd r0, r1, [r1], #4
    .long 0xe0c100d4

.BHI12:
    cmp r0, #1
    bhi .BHI13

.INVALID12:
    @ invalid: ldrd r0, r1, [r2], r0
    .long 0xe08200d0

.BHI13:
    cmp r0, #1
    bhi .BHI14

.INVALID13:
    @ invalid: ldrd r0, r1, [r2, r0]
    .long 0xe18200d0

.BHI14:
    cmp r0, #1
    bhi .BHI15

.INVALID14:
    @ invalid: ldrd r0, r1, [r2, r0]!
    .long 0xe1a200d0

.BHI15:
    cmp r0, #1
    bhi .BHI16

.INVALID15:
    @ invalid: ldrd r0, r1, [r2], r1
    .long 0xe08200d1

.BHI16:
    cmp r0, #1
    bhi .BHI17

.INVALID16:
    @ invalid: ldrd r0, r1, [r2, r1]
    .long 0xe18200d1

.BHI17:
    cmp r0, #1
    bhi .call_thumb

.INVALID17:
    @ invalid: ldrd r0, r1, [r2, r1]!
    .long 0xe1a200d1

.call_thumb:

    blx thumbfunc


.exit:
    ldr r0, =ok_str
    bl puts

    mov r0, #0
    pop { pc }

.thumb
thumbfunc:
.BHI18:
    cmp r0, #1
    bhi .BHI19

.INVALID18_THUMB:
    @invalid: ldrd r0, sp, [r1], #4
    .short 0xe8f1
    .short 0x0d01

.BHI19:
    cmp r0, #1
    bhi .BHI20

.INVALID19_THUMB:
    @invalid: ldrd r0, pc, [r1], #4
    .short 0xe8f1
    .short 0x0f01

.BHI20:
    cmp r0, #1
    bhi .BHI21

.INVALID20_THUMB:
    @invalid: ldrd sp, r0, [r1], #4
    .short 0xe8f1
    .short 0xd001

.BHI21:
    cmp r0, #1
    bhi .exit_thumb

.INVALID21_THUMB:
    @invalid: ldrd pc, r0, [r1], #4
    .short 0xe8f1
    .short 0xf001

.exit_thumb:
    bx lr

.section .rodata
ok_str:
    .ascii "OK\n\0"

some_data:
    .long 0xdeadbeef
