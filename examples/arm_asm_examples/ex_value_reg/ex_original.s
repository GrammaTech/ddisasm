    .arch armv7-a

    .section    .rodata
    .align    2
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
    asr     r1, r0, #10
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0xffe60000
    bl  fun
    #------------------------
    mov     r0, #0x98000000
    mov     r1, #10
    asr     r1, r0, r1
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0xffe60000
    bl  fun
    #------------------------
    mov     r0, #1
    lsl     r1, r0, #12
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0x10000
    bl  fun
    #------------------------
    mov     r0, #1
    mov     r1, #12
    lsl     r1, r0, r1
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0x10000
    bl  fun
    #------------------------
    mov     r1, #0xf0f0
    mov     r2, #0xff
    and     r1, r1, r2
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xf0f0
    and     r1, r1, #0xff
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xff00
    mov     r2, #0xff
    orr     r1, r1, r2
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xffff
    bl  fun
    #------------------------
    mov     r1, #0xff00
    orr     r1, r1, #0xff
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xffff
    bl  fun
    #------------------------
    mov     r1, #0xf00
    mov     r2, #0xff0
    eor     r1, r1, r2
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xf0
    bl  fun
    #------------------------
    mov     r1, #0xf00
    eor     r1, r1, #0xff0
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # Value = 0xf0
    bl  fun

    #------------------------
    mov     r0, #0x68000000
    lsr     r1, r0, #10
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0x1a0000
    bl  fun
    #------------------------
    mov     r0, #0x98000000
    mov     r1, #10
    lsr     r1, r0, r1
    cmp     r1, #0
    it eq
    ldreq   r1, [r1]
    mov     r0, r1
    # r0 value = 0x260000
    bl  fun
    #------------------------
.thumb
    movs    r3, #0
    mov    r0, r3
    pop    {r7, pc}
