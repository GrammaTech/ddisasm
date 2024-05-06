
# Patterns for moving values through the stack

    .align 16
    .globl  main
    .type   main, @function
main:
push_pop:
    pushq   %rbp
    movq    %rsp, %rbp
    leaq    .hello_ptr(%rip), %rdx
    push    %rdx
    xor     %rdx, %rdx
    pop     %rdx
    movq    (%rdx), %rdi
    call    puts@PLT

# Push several immediates to the stack
# and pop them later

nested_push_imm:
    leaq    .aaa(%rip), %rdx
    pushw   $2
    pushq   $4
    pushq   %rdx
    xor     %rdx, %rdx

    popq    %rdi
pop_4:
    popq    %rsi
    movb     $0x42, (%rsi,%rdi)
    call    puts@PLT

    leaq    .aaa(%rip), %rdi
    xor     %rax,%rax
pop_2:
    popw    %ax
    movb     $0x43, (%rdi,%rax)
    call    puts@PLT

# Push several immediates to the stack
# and read them later without popping them

push_load:

    leaq    .aaa(%rip), %rdx
    pushq   $2
    pushw   $4
    pushq   %rdx
    xor     %rdx, %rdx

    movq    (%rsp),%rdi
    xor     %rsi,%rsi
read_4:
    movw    8(%rsp),%si
    movb     $0x44, (%rsi,%rdi)
    call    puts@PLT

    leaq    .aaa(%rip), %rdi
read_2:
    movq    10(%rsp),%rsi
    movb     $0x45, (%rsi,%rdi)
    call    puts@PLT

    add     $18, %rsp

# Push some registers to the stack
# and read them later

push_regs:
    leaq    .aaa(%rip), %rdx
    mov     $1, %rax
    pushq   %rax
    mov     $3, %ax
    pushw   %ax
    pushq   %rdx
    xor     %rdx, %rdx

    movq    (%rsp),%rdi
    xor     %rsi,%rsi
read_3:
    movw    8(%rsp),%si
    movb     $0x44, (%rsi,%rdi)
    call    puts@PLT

    leaq    .aaa(%rip), %rdi
read_1:
    movq    10(%rsp),%rsi
    movb     $0x45, (%rsi,%rdi)
    call    puts@PLT

    add     $18, %rsp
    xor     %rax,%rax
    popq    %rbp
    ret



.data

.hello_ptr:
    .quad .hello
.hello:
    .string "hello\n"
.aaa:
    .string "AAAAAAAAAAAAAA\n"
