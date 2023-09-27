
    .section .rodata
.LC0:
    .string "%d\n"
    .quad   .L_dummy

    .text

.globl foo
.type foo, @notype
foo:
    pushq   %rbp
    pushq   %rcx
    movq    %rsp, %rbp
    movq    %rdi, %rcx
    leaq    _TLS_MODULE_BASE_@TLSLD(%rip),%rdi
# This label initially splits blocks between the lea and call instructions
# to check whether the tls_get_addr pattern is correctly recognized.
.L_dummy:
    callq   __tls_get_addr@PLT
    movl    %esi,.L_TLS8@DTPOFF(%rax)
    movl    %ecx,.L_TLS12@DTPOFF(%rax)
    movq    $0, %rax
    popq    %rcx
    popq    %rbp
    ret

    .align 16
    .globl  bar
    .type   bar, @function
bar:
.LFB6:
    pushq   %rbp
    movq    %rsp, %rbp
    movl    $20, %esi
    movl    $10, %edi
    call    foo@PLT
    leaq    _TLS_MODULE_BASE_@TLSLD(%rip),%rdi
    callq   __tls_get_addr@PLT
    xorq    %rsi,%rsi
    movl    .L_TLS8@DTPOFF(%rax),%esi
    movl    .L_TLS12@DTPOFF(%rax),%edi
    addl    %edi, %esi
    leaq    .LC0(%rip), %rdi
    call    printf@PLT
    movq    $0, %rax
    movl    $0, %eax
    popq    %rbp
    ret

.LFE6:
    .size    bar, .-bar

    .section .tdata,"wa",@progbits
.align 8
_TLS_MODULE_BASE_:
.L_TLS0:
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x0
    .byte 0x80

    .section .tbss ,"wa",@nobits
.L_TLS8:
    .zero 4
.L_TLS12:
    .zero 4
