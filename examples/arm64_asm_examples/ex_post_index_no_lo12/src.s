# Ensure that post-index operands do not get :lo12: attributes.

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-64]!

    # load the addr of the structure.
    adrp x8,my_struct
    mov x0,#0

    # Looks like a split-load, except that :lo12: is not allowed in post-index
    # operands.
    ldr x1,[x8],#8

    adrp x0, my_string
    add x0, x0, :lo12:my_string
    bl printf

.exit:
    ldp fp,lr,[sp],#64
    mov x0, #0
    ret

.section .rodata
# ensure we are page-aligned.
.balign 4096
my_struct:
    .quad 1234

my_string:
.asciz "my number is: %d\n"
