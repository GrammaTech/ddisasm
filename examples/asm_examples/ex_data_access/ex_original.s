
    .section .rodata
.LC0:
    .string "%d\n"

    .text

.globl foo
.type foo, @notype
foo:
    pushq   %rbp
    movq    %rsp, %rbp

    xor    %r8, %r8
    xor    %r9, %r9
    xor    %r10, %r10
    xor    %r11, %r11

    imul    r0_mul(%rip), %r8
    movq    r1_add(%rip), %r9
    xor     %r8, %r9
    movq    r2_add(%rip), %r10
    xor     %r8, %r10
    movq    r3_add(%rip), %r11
    xor     %r8, %r11
    movq    %r8, %rsi
    leaq    .LC0(%rip), %rdi
    movq    $0, %rax
    call    printf@PLT
    movq    $0, %rax
    popq    %rbp
    ret

r0_mul:
    # This happens to appear code as follows:
    # sub $0x2d4c957f,%eax
    # hlt
    # push %rcx
    # pop %rax
    .byte 0x2d
    .byte 0x7f
    .byte 0x95
    .byte 0x4c
    .byte 0x2d
    .byte 0xf4
    .byte 0x51
    .byte 0x58
r1_add:
    # This happens to appear code as follows:
    # cld
    # movabs 0xd846810a978a59f5,%eax
    .byte 0xfc
    .byte 0xa1
    .byte 0xf5
    .byte 0x59
    .byte 0x8a
    .byte 0x97
    .byte 0xa
    .byte 0x81
r2_add:
    # This happens to appear code as follows:
    # rex.RX fadd %st(2),%st
    # cmp %bl,%bh
    # cltd
    # jo ..
    .byte 0x46
    .byte 0xd8
    .byte 0xc2
    .byte 0x38
    .byte 0xdf
    .byte 0x99
    .byte 0x70
    .byte 0xa7
r3_add:
    # This happens to appear code as follows:
    # pop %rsp
    # rex.WB and -0x7ed946e4(%r15),%dil
    .byte 0x5c
    .byte 0x49
    .byte 0x22
    .byte 0xbf
    .byte 0x1c
    .byte 0xb9
    .byte 0x26
    .byte 0x81

    .align 16
    .globl  main
    .type   main, @function
main:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $20, %esi
    movl    $10, %edi
    call    foo
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main
