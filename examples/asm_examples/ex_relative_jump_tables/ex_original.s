// this example contains a switch table where

    .text
    .intel_syntax noprefix
    .file	"ex.c"

# -- Begin function one
    .globl	one
    .p2align	4, 0x90
    .type	one,@function
one:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end0:
.size	one, .Lfunc_end0-one
# -- End function

# -- Begin function two
    .globl	two
    .p2align	4, 0x90
    .type	two,@function
two:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.1]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end1:
.size	two, .Lfunc_end1-two
# -- End function

# -- Begin function three
    .globl	three
    .p2align	4, 0x90
    .type	three,@function
three:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.2]
    call	puts@PLT
    lea	eax, [rbx + 1]
    pop	rbx
    ret
.Lfunc_end2:
.size	three, .Lfunc_end2-three
# -- End function

# -- Begin function four
    .globl	four
    .p2align	4, 0x90
    .type	four,@function
four:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.3]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end3:
.size	four, .Lfunc_end3-four
# -- End function

# -- Begin function five
    .globl	five
    .p2align	4, 0x90
    .type	five,@function
five:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.4]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end4:
.size	five, .Lfunc_end4-five
# -- End function

# -- Begin function six
    .globl	six
    .p2align	4, 0x90
    .type	six,@function
six:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.5]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end5:
.size	six, .Lfunc_end5-six
# -- End function

# -- Begin function def
    .globl	def
    .p2align	4, 0x90
    .type	def,@function
def:
    push	rbx
    mov	ebx, edi
    lea	rdi, [rip + .L.str.6]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end6:
.size	def, .Lfunc_end6-def
# -- End function

# -- Begin function fun
    .globl	fun
    .p2align	4, 0x90
    .type	fun,@function
fun:
    push	rbp
    push	r9
    push	r10
    push	r12
    push	r14
    push	rbx
    mov rbp, rsp
    mov	r13d, esi
    mov	ebx, edi
    cmp	ebx, r13d
    jge	.LBB5_10
    lea	r14, [rip + .jump_table_A]
    mov [rbp-8], r14
    mov r14, [rbp-8]
    .p2align	4, 0x90
.LBB5_2:
    lea	r9, [rip + .jump_table_B]
    lea	eax, [rbx - 1]
    cmp	eax, 1
    ja	.LBB5_8
    movsxd	rax, dword ptr [r14 + 4*rax]
    add	rax, r14
    jmp	rax
.jump_table_target1:
    mov	edi, ebx
    call	one
    test rbx, 1
    jnz .L_odd1
    mov     r12, 2
    jmp .L_end1
.L_odd1:
    mov     r12, 3
.L_end1:
    movsxd  rax, dword ptr [r9 + 4*r12]
    add rax, r9
    jmp rax
    .p2align	4, 0x90
.LBB5_8:
    mov	edi, ebx
    call	def
    jmp	.LBB5_9
    .p2align	4, 0x90
.jump_table_target2:
    mov	edi, ebx
    call	two
    test rbx, 1
    jnz .L_odd2
    mov     r12, 0
    jmp .L_end2
.L_odd2:
    mov     r12, 1
.L_end2:
    movsxd  rax, dword ptr [r9 + 4*r12]
    add rax, r9
    jmp rax
    .p2align	4, 0x90
.jump_table_target3:
    mov	edi, ebx
    call	three
    test rbx, 1
    jnz .L_odd3
    mov     r12, 4
    jmp .L_end3
.L_odd3:
    mov     r12, 5
.L_end3:
    movsxd  rax, dword ptr [r10 + 4*r12]
    add rax, r10
    jmp rax
    .p2align	4, 0x90
.jump_table_target4:
    mov	edi, ebx
    call	four
    lea	r10, [rip + .jump_table_C]
    jmp	.LBB5_9
    .p2align	4, 0x90
.jump_table_target5:
    mov	edi, ebx
    call	five
    jmp	.LBB5_9
    .p2align	4, 0x90
.jump_table_target6:
    mov	edi, ebx
    call	six
    .p2align	4, 0x90
.LBB5_9:
    add	ebx, 1
    cmp	r13d, ebx
    jne	.LBB5_2
.LBB5_10:
    pop	rbx
    pop	r14
    pop	r12
    pop	r10
    pop	r9
    pop	rbp
    ret
.Lfunc_end8:
    .size	fun, .Lfunc_end8-fun
    .section	.rodata,"a",@progbits
    .p2align	2

// here we have tables of relative offsets (symbol minus symbol)
.jump_table_A:
    .long	.jump_table_target1-.jump_table_A
    .long	.jump_table_target2-.jump_table_A
.jump_table_B:
    .long	.jump_table_target1-.jump_table_B
    .long	.jump_table_target2-.jump_table_B
    .long	.jump_table_target3-.jump_table_B
    .long	.jump_table_target4-.jump_table_B
.jump_table_C:
    .long	.jump_table_target1-.jump_table_C
    .long	.jump_table_target2-.jump_table_C
    .long	.jump_table_target3-.jump_table_C
    .long	.jump_table_target4-.jump_table_C
    .long	.jump_table_target5-.jump_table_C
    .long	.jump_table_target6-.jump_table_C
# -- End function

    .text
# -- Begin function main
    .globl	main
    .p2align	4, 0x90
    .type	main,@function
main:
    push	rax
    lea	rdi, [rip + .L.str.7]
    call	puts@PLT
    mov	edi, 1
    mov	esi, 6
    call	fun
    xor	eax, eax
    pop	rcx
    ret
.Lfunc_end7:
    .size	main, .Lfunc_end7-main
# -- End function


    .type	.L.str,@object          # @.str
    .section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
    .asciz	"one"
    .size	.L.str, 4

    .type	.L.str.1,@object        # @.str.1
.L.str.1:
    .asciz	"two"
    .size	.L.str.1, 4

    .type	.L.str.2,@object        # @.str.2
.L.str.2:
    .asciz	"three"
    .size	.L.str.2, 6

    .type	.L.str.3,@object        # @.str.3
.L.str.3:
    .asciz	"four"
    .size	.L.str.3, 5

    .type	.L.str.4,@object        # @.str.4
.L.str.4:
    .asciz	"five"
    .size	.L.str.4, 5

    .type	.L.str.5,@object        # @.str.5
.L.str.5:
    .asciz	"six"
    .size	.L.str.5, 5

    .type	.L.str.6,@object        # @.str.6
.L.str.6:
    .asciz	"last"
    .size	.L.str.6, 5

    .type	.L.str.7,@object        # @.str.7
.L.str.7:
    .asciz	"!!!Hello World!!!"
    .size	.L.str.7, 18


    .ident	"clang version 6.0.0 (tags/RELEASE_600/final)"
    .section	".note.GNU-stack","",@progbits
