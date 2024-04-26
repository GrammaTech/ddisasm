// Similar to ex_relative_jump_tables except that in this example, there are
// memory writes between the bound check instruction (`cmp`) and the
// corresponding `jmp`.
//
// This example is to demonstrate that `jump_table_B` and `jump_table_D` are
// correctly resolved when we have a bound-check pattern as the following
// example where a value at memory is compared to a constant, and the value is
// loaded right after the corresponding jump:
//
// cmp dword ptr [rdx], 31
// ...
// ja target
// mov ecx, dword ptr [rdx]
//
// We make sure that up to 2 instructions between cmp and jmp are not a
// memory-write to the same memory location that the `cmp` compares with.
// As long as the memory operands are syntactically different, we assume that
// they do not alias.

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
    push	r13
    push	rbx
    mov rbp, rsp
    mov	r13d, esi
    mov	ebx, edi
    cmp	ebx, r13d
    jge	.LBB5_10
.LBB5_2:
    lea	eax, [rbx - 1]
    cmp	eax, 1
    ja  .LBB5_9
    jbe .target1
    jmp .target2
.target1:
    lea	r9, [rip + .jump_table_A]
    mov	edi, ebx
    call	one
    lea r12, dword ptr [rip + bound]
    test rbx, 1
    jnz .L_odd1
    mov dword ptr [r12], 1
    jmp .L_end1
.L_odd1:
    mov dword ptr [r12], 2
.L_end1:
    cmp dword ptr [r12], 4
    mov dword ptr [r12 + 4], 7
    mov r10d, dword ptr [r12 + rbx*4]
    jbe .L_jump1
    jmp .LBB5_9
.L_jump1:
    mov r12d, dword ptr [r12]
    lea	r10, [rip + .jump_table_B]
    movsxd  rax, dword ptr [r9 + 4*r12]
    add rax, r9
    jmp rax
    .p2align	4, 0x90
.target2:
    lea	r9, [rip + .jump_table_C]
    mov	edi, ebx
    call	one
    lea r12, dword ptr [rip + bound]
    test rbx, 1
    jnz .L_odd2
    mov dword ptr [r12], 1
    jmp .L_end2
.L_odd2:
    mov dword ptr [r12], 2
.L_end2:
    cmp dword ptr [r12], 4
    mov dword ptr [r12 + rbx*4], ebx
    lea	r10, [rip + .jump_table_D]
    jbe .L_jump2
    jmp .LBB5_9
.L_jump2:
    mov r12d, dword ptr [r12]
    movsxd  rax, dword ptr [r9 + 4*r12]
    add rax, r9
    jmp rax
    .p2align	4, 0x90
.jump_table_target3:
    mov edi, ebx
    call    three
    test rbx, 1
    jnz .L_odd3
    mov     r12, 32
    jmp .L_end3
.L_odd3:
    mov     r12, 33
.L_end3:
    sub r12, 32
    movsxd  rax, dword ptr [r10 + 4*r12]
    add rax, r10
    jmp rax
    .p2align    4, 0x90
.jump_table_target4:
    mov	edi, ebx
    call	four
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
.LBB5_9:
    add ebx, 1
    cmp r13d, ebx
    jne .LBB5_2
.LBB5_10:
    pop	rbx
    pop	r13
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
    .long	.target1-.jump_table_A
    .long	.jump_table_target3-.jump_table_A
    .long	.jump_table_target4-.jump_table_A
.jump_table_B:
    .long	.jump_table_target5-.jump_table_B
    .long	.jump_table_target6-.jump_table_B
.jump_table_C:
    .long	.target1-.jump_table_C
    .long	.jump_table_target3-.jump_table_C
    .long	.jump_table_target4-.jump_table_C
.jump_table_D:
    .long	.jump_table_target5-.jump_table_D
    .long	.jump_table_target6-.jump_table_D
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


    .data
    .align 8
bound:
    .zero 64

    .ident	"clang version 6.0.0 (tags/RELEASE_600/final)"
    .section	".note.GNU-stack","",@progbits
