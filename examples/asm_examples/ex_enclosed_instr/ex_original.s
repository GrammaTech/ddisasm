
    .section .rodata
.LC0:
    .string "%d\n"
    .quad  .L0+3
    .zero  7
    .quad  .L1+3
.LC1:
    .quad  .L0

    .text

    .type foo, @notype
foo:
    pushq   %rbp
    movq    %rsp, %rbp

    addq    %rdi, %rsi
    leaq    .LC0(%rip), %rdi
    movq    $0, %rax
    call    printf@PLT
    movq    $0, %rax
    popq    %rbp
    ret

    .type   bar, @notype
bar:
    pushq   %rbp
    movq    %rsp, %rbp
    jmp     .L2
    ja      .L2
    nop
    nop
    nop
.L0:
    movl    $5, %edi
.L1:
    # At .L1+3, there is an overlapping `ADD` block A of size 2, which is
    # enclosed by the `MOV` instruction in block .L1.
    # This example is to demonstrate that .L1 wins over A
    # by block_point("dangling block with enclosed instr").
    movl    $4, %esi
    call    foo
    jmp     .L3
.L2:
    jmp     *.LC1(%rip)
.L3:
    movl    $0, %eax
    popq    %rbp
    ret

    .align 16
    .globl  main
    .type   main, @notype
main:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
    call    bar
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    main, .-main
