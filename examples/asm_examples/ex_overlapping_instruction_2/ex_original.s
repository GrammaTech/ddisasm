
    .text

    .align 16
    .globl  main
    .type   main, @function
main:
.LFB6:
    pushq    %rbp
    movq    %rsp, %rbp

    movq    $1, %rax
    movq    $1, %rcx
    movq    $1, %rdx
    cmpl    $0, %ecx
    # This conditional jump ensures .L1+1 is not a known block
    jz .L3

    cmpl    $0, %ecx
    jz      .L1+1
.L1:
    lock    cmpxchgq %rcx,mydata(%rip)
    cmpq    %rdx,%rcx
    je      .L2
    leaq    .LC0(%rip),%rdi
    movq    $7,%rsi
    call    printf@PLT
    jmp     .L3
.L2:
    leaq    .LC0(%rip),%rdi
    movq    $8,%rsi
    call    printf@PLT
.L3:
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size   main, .-main

    .section .rodata
.LC0:
    .string "%d\n"

    .section .data

    .type mydata,@object
    .size mydata,8
mydata:
    .byte 0x1
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
