
# Patterns for moving values through the stack

    .align 16
    .globl  main
    .type   main, @function
main:
    pushl   %ebp
    movl    %esp, %ebp


    call	__x86.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
    leal    .hello_ptr@GOTOFF(%ebx), %edx
    push    %edx
    xor     %edx, %edx
    pop     %edx
    movl    (%edx), %edi

    sub     $12, %esp
    push    %edi
    call    puts@PLT
    add     $16, %esp

# Push several immediates to the stack
# and pop them later

nested_push_imm:
    leal    .aaa@GOTOFF(%ebx), %edx
    pushw   $2
    pushl   $4
    pushl   %edx
    xor     %edx, %edx

    popl    %edi
pop_4:
    popl    %esi
    movb     $0x42, (%esi,%edi)

    push    %edi
    call    puts@PLT
    add     $4, %esp

    leal    .aaa@GOTOFF(%ebx), %edi
    xor     %eax,%eax
pop_2:
    popw    %ax
    movb     $0x43, (%edi,%eax)

    push    %edi
    call    puts@PLT
    add     $4, %esp

# Push several immediates to the stack
# and read them later without popping them

push_load:

    leal    .aaa@GOTOFF(%ebx), %edx
    pushl   $2
    pushw   $4
    pushl   %edx
    xor     %edx, %edx

    movl    (%esp),%edi
    xor     %esi,%esi
read_4:
    movw    4(%esp),%si
    movb     $0x44, (%esi,%edi)

    push    %edi
    call    puts@PLT
    add     $4, %esp

    leal    .aaa@GOTOFF(%ebx), %edi
read_2:
    movl    6(%esp),%esi
    movb     $0x45, (%esi,%edi)


    push    %edi
    call    puts@PLT
    add     $4, %esp

    add     $10, %esp

# Push some registers to the stack
# and read them later

push_regs:
    leal    .aaa@GOTOFF(%ebx), %edx
    mov     $1, %eax
    pushl   %eax
    mov     $3, %ax
    pushw   %ax
    pushl   %edx
    xor     %edx, %edx

    movl    (%esp),%edi
    xor     %esi,%esi
read_3:
    movw    4(%esp),%si
    movb     $0x44, (%esi,%edi)

    push    %edi
    call    puts@PLT
    add     $4, %esp

   leal    .aaa@GOTOFF(%ebx), %edi
read_1:
    movl    6(%esp),%esi
    movb     $0x45, (%esi,%edi)

    push    %edi
    call    puts@PLT
    add     $4, %esp

    add     $10, %esp
    xor     %eax,%eax

    popl    %ebp
end:
    ret



.data

.hello_ptr:
    .long .hello
.hello:
    .string "hello\n"
.aaa:
    .string "AAAAAAAAAAAAAA\n"
