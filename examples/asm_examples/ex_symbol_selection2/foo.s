    .section .rodata
.LC0_foo:
    .string "foo: %d\n"

    .text

.type  __fun, @function
__fun:
.globl fun
.type  fun, @function
fun:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    $7, %rsi
    leaq    .LC0_foo(%rip), %rdi
    call    printf@PLT
    movq    $0, %rax
    popq    %rbp
    ret

    .align 16

.globl foo_fun
.type  foo_fun, @function
foo_fun:
    pushq   %rbp
    movq    %rsp, %rbp
    movq    $8, %rsi
    leaq    mydata_local(%rip), %rdi
    call    *(%rdi)
    leaq    mydata_global(%rip), %rdi
    call    *(%rdi)
    movq    $0, %rax
    popq    %rbp
    ret

    .align 16

.section .data.rel.ro ,"wa",@progbits

mydata_local:
    .quad __fun
mydata_global:
    .quad fun
