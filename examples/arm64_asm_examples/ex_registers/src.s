# Test special register names

.arch armv8-a
.file "src.s"
.text
.global main
.type main, %function
main:
    stp fp,lr,[sp,#-16]!

    adrp lr, .hello_lr
    add x0, lr, #:lo12:.hello_lr

    bl printf

    adrp fp, .hello_fp
    add x0, fp, #:lo12:.hello_fp

    bl printf

.exit:
    ldp fp,lr,[sp],#16
    mov x0, #0
    ret

.section .rodata
.hello_lr:
    .asciz "hello lr\n"
.hello_fp:
    .asciz "hello fp\n"
