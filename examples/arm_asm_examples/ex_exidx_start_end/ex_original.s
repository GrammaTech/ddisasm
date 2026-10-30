# Reference the linker-provided __exidx_start/__exidx_end symbols through the
# GOT, as the ARM EHABI unwinder (__gnu_Unwind_Find_exidx) does in
# executables that link libgcc's unwinder statically.
#
# __exidx_start is the start of .ARM.exidx, which is also the end of
# .ARM.extab. ddisasm must symbolize these GOT entries with
# __exidx_start/__exidx_end; a generic label would end up in a section the
# pretty-printer does not emit, and reassembly would fail to link.

    .syntax unified
    .arch armv7-a
    .arm

    .text
    .align 2
    .global main
    .type main, %function
main:
    .fnstart
    push {r4, r5, r6, lr}
    .save {r4, r5, r6, lr}

    ldr r6, .L_got_base
.L_pic:
    add r6, pc, r6

    ldr r4, .L_got_exidx_start
    ldr r4, [r6, r4]
    ldr r5, .L_got_exidx_end
    ldr r5, [r6, r5]

    # The table may be empty (e.g., in a rewritten binary), but it must not be
    # inverted and must hold a whole number of 8-byte entries.
    subs r0, r5, r4
    blt .L_fail
    tst r0, #7
    bne .L_fail

    adr r0, .L_ok_msg
    bl puts
    mov r0, #0
    pop {r4, r5, r6, pc}

.L_fail:
    adr r0, .L_fail_msg
    bl puts
    mov r0, #1
    pop {r4, r5, r6, pc}

    .align 2
.L_got_base:
    .word _GLOBAL_OFFSET_TABLE_ - (.L_pic + 8)
.L_got_exidx_start:
    .word __exidx_start(GOT)
.L_got_exidx_end:
    .word __exidx_end(GOT)
.L_ok_msg:
    .asciz "exidx OK"
.L_fail_msg:
    .asciz "exidx FAIL"
    .align 2
    .fnend
    .size main, .-main

    .section .note.GNU-stack,"",%progbits
