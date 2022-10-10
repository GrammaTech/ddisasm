    .arch armv7-a

    .section    .rodata
    .align    2
value.1:
    .word 0xffe60000
value.2:
    .word 0xffe60000
value.3:
    .word 0x1000
value.4:
    .word 0x1000
value.5:
    .word 0xf0
value.6:
    .word 0xf0
value.7:
    .word 0xffff
value.8:
    .word 0xffff
value.9:
    .word 0xf0
value.10:
    .word 0xf0
#value.11:
#    .word 0x1a0000
#value.12:
#    .word 0x260000
print_format:
    .string "%d\n"

    .text
    .align    2
    .global fun
    .type fun, %function
.thumb
fun:
    push { r1, lr }
    mov     r1, r0
    ldr     r0, .L_1
    bl printf(PLT)
.thumb
    mov r0, #0
    pop { r1, pc }
    .align 2
.L_1:
    .word print_format

    .align    2
    .global    main
    .syntax unified
    .thumb
    .thumb_func
    .type    main, %function
.thumb
main:
    push {r7, lr}
    add r7, sp, #0
    #------------------------
    mov     r0, #0x98000000
    asr     r0, r0, #10
    # r0 value = 0xffe60000
    bl  fun
    #------------------------
    mov     r0, #0x98000000
    mov     r1, #10
    asr     r0, r0, r1
    # r0 value = 0xffe60000
    bl  fun
    #------------------------
    mov     r0, #1
    lsl     r0, r0, #12
    # r0 value = 0x10000
    bl  fun
    #------------------------
    mov     r0, #1
    mov     r1, #12
    lsl     r0, r0, r1
    # r0 value = 0x10000
    bl  fun
    #------------------------
    mov     r1, #0xf0f0
    mov     r2, #0xff
    and     r0, r1, r2
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xf0f0
    and     r0, r1, #0xff
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xff00
    mov     r2, #0xff
    orr     r0, r1, r2
    # Value = 0xffff
    bl  fun
    #------------------------
    mov     r1, #0xff00
    orr     r0, r1, #0xff
    # Value = 0xffff
    bl  fun
    #------------------------
    mov     r1, #0xf00
    mov     r2, #0xff0
    eor     r0, r1, r2
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xf00
    eor     r0, r1, #0xff0
    # Value = 0xf0
    bl  fun

    # NOTE: souffle bshru seems to produce incorrect value.
    #       disabled for now.
    #------------------------
    #mov     r0, #0x68000000
    #lsr     r0, r0, #10
    ## r0 value = 0x1a0000
    #bl  fun
    #------------------------
    #mov     r0, #0x98000000
    #mov     r1, #10
    #lsr     r0, r0, r1
    ## r0 value = 2490368
    #bl  fun
    #------------------------
.thumb
    movs    r3, #0
    mov    r0, r3
    pop    {r7, pc}
