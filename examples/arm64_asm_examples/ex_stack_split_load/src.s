# Test a split load where the base is saved to the stack and restored later
# before adding the offset.

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-64]!

    adrp x4, .s_hello
    adrp x5, .s_world
    adrp x6, .s_goodbye
    adrp x7, :got:number

    # Test both paired and single load/store
    stp x4, x5, [sp, #32]
    str x6, [sp, #16]
    str x7, [sp, #24]

    # A loop to complicate the CFG between stack push/pop
    mov x4, #0
.loop:
    add x4, x4, #1
    cmp x4, #10
    b.lt .loop

    # Use different registers than what was used previously.
    ldp x0, x24, [sp, #32]
    ldr x25, [sp, #16]
    ldr x26, [sp, #24]

    add x0, x0, #:lo12:.s_hello
    bl printf

    add x0, x24, #:lo12:.s_world
    ldr x26, [x26, #:got_lo12:number]
    ldr x1, [x26]
    bl printf

    add x0, x25, #:lo12:.s_goodbye
    bl printf

.exit:
    ldp fp,lr,[sp],#64
    mov x0, #0
    ret

.section .rodata
.s_hello:
    .asciz "hello "
.s_world:
    .asciz "world %d\n"
.s_goodbye:
    .asciz "goodbye\n"

.global number
.type number, @object
number:
    .long 42
