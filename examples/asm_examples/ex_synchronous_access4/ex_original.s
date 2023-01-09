    .text

    .type   unreachable, @function
unreachable:
    xorq    %rcx, %rcx
    xorq    %rdi, %rdi
.LC0:
    # The following two accesses appear synchronized accesses.
    # However, they should not be detected as such because PADDING+260
    # is across my_symbol.
    movups  PADDING(%rdi,%rcx,8), %xmm0
    movups  PADDING+260(%rdi,%rcx,8), %xmm1
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
    movl    my_symbol(%rip), %edi
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main

    .data

    .type PADDING, @object
    .size PADDING, 256
PADDING:
    .zero 256

    .type my_symbol, @object
    .size my_symbol, 64
my_symbol:
    .zero 64
