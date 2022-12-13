    .text

    .type   unreachable, @function
unreachable:
    xorq    %rcx, %rcx
    xorq    %rdi, %rdi
.LC0:
    # The following two access appear a synchronized access,
    # but it should not be detected as since PADDING+16 is `stdout`.
    movups  PADDING(%rdi,%rcx,8), %xmm0
    movups  PADDING+16(%rdi,%rcx,8), %xmm1
    movups  %xmm0, -16(%rax,%rbp)
    movups  %xmm1, (%rax,%rbp)
    addq    $8, %rcx
    jz      .LC0
    ret

    .globl  main
    .type   main, @function
main:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $65, %edi
    movq    stdout(%rip), %rsi
    callq   fputc@PLT
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main

    .data

    .type PADDING, @object
    .size PADDING, 16
PADDING:
    .zero 16

    .bss

    .symver stdout_copy,stdout_copy@GLIBC_2.2.5
    .globl stdout_copy
    .type stdout_copy, @object
    .size stdout_copy, 8
stdout_copy:
    .zero 8
