    // This example contains LEAs with symbolic expressions as displacement.
    // See the labels `lea_sym_minus_sym1` and `lea_sym_minus_sym2`.

    .text
    .intel_syntax noprefix
    .globl	one                     # -- Begin function one
    .p2align   4, 0x90
    .type	one,@function
one:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret

    .globl	two                     # -- Begin function two
    .p2align   4, 0x90
    .type	two,@function
two:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.1]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret

    .globl	fun                     # -- Begin function fun
    .p2align	4, 0x90
    .type	fun,@function
fun:
    push	rbp
    push	r14
    push	rbx
    push	r9
    mov	ebp, esi
    mov	ebx, edi
    cmp	ebx, ebp
    jge	.L3
    lea	r14, [rip + jump_table]
loop_header:                        # =>This Inner Loop Header: Depth=1
    lea	eax, [rbx - 1]
    cmp	eax, 1
    ja	.L0
jumping_block:
    movsxd	rax, dword ptr [r14 + 4*rax]
    add	rax, r14
    jmp	rax
jt_target_1:                        #   in Loop: Header=BB5_2 Depth=1
    mov	edi, ebx
    call	one
    jmp .L2
.L0:                                #   in Loop: Header=BB5_2 Depth=1
    mov	edi, ebx
    jmp	.L2
lea_sym_minus_sym1:
    lea r9, qword ptr [rax + target2 - lea_sym_minus_sym1]
    cmp rbx, rdi
    jb .L1
lea_sym_minus_sym2:
    lea r9, qword ptr [r9 + target1 - target2]
.L1:
    jmp r9
target1:
    mov	edi, ebx
    call	one
    jmp .L2
target2:
    mov	edi, ebx
    call	two
.L2:
    add	ebx, 1
    cmp	ebp, ebx
    jne	loop_header
.L3:
    pop	r9
    pop	rbx
    pop	r14
    pop	rbp
    ret

    .globl	main                    # -- Begin function main
    .type	main,@function
    .p2align   4, 0x90
main:
    push	rax
    lea	rdi, [rip + .L.str.5]
    call	puts@PLT
    mov	edi, 1
    mov	esi, 6
    call	fun
    xor	eax, eax
    pop	rcx
    ret

    .section	.rodata,"a",@progbits
    .p2align	2

// here we have a table of relative offsets (symbol minus symbol)
jump_table:
    .long	jt_target_1-jump_table
    .long	lea_sym_minus_sym1-jump_table

    .section	.rodata.str1.1,"aMS",@progbits,1

    .type	.L.str,@object
.L.str:
    .asciz	"one"
    .size	.L.str, 4

    .type	.L.str.1,@object
.L.str.1:
    .asciz	"two"
    .size	.L.str.1, 4

    .type	.L.str.5,@object
.L.str.5:
    .asciz	"!!!Hello World!!!"
    .size	.L.str.5, 18
