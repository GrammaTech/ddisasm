
.section .rodata
    .align 8
.LC:
    .string "tls_var value: %d\n"

.section .text ,"wa"

    .align 16
    .globl  get_tls_var
    .type   get_tls_var, @function
get_tls_var:
    pushq   %rbp
    movq    %rsp, %rbp
var_tpoff_1:
    movq    $var@tpoff, %rax
    movq    %fs:0(%rax),%rax
    popq    %rbp
    ret

    .size    get_tls_var, .-get_tls_var

    .align 16
    .globl  set_tls_var
    .type   set_tls_var, @function
set_tls_var:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    %rdi, -8(%rbp)
var_tpoff_2:
    movq    $var@tpoff, %rax
    movq    -8(%rbp), %rdx
    movq    %rdx, %fs:0(%rax)
    nop
    popq    %rbp
    ret

    .size    set_tls_var, .-set_tls_var

    .align 16
    .globl  main
    .type   main, @function
main:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    $7, %rdi
    call    set_tls_var@PLT
    movq    %rax, %rdi
    call    get_tls_var@PLT
    movq    %rax, %rsi
    leaq    .LC(%rip), %rdi
    call    printf@PLT
    movl    $0, %eax
    popq    %rbp
    ret

    .size    main, .-main

.section .tbss ,"wa",@nobits

    .align 8
var:
    .zero 8
