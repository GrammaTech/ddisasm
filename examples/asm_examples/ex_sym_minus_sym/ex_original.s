    // this example contains a switch table where the differences of two symbols
    // are what is stored

    .text
    .intel_syntax noprefix
    .file	"ex.c"
    .globl	one                     # -- Begin function one
    .p2align	4, 0x90
    .type	one,@function
one:                                    # @one
    .cfi_startproc
# %bb.0:
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov	ebx, edi
    lea	rdi, [rip + .L.str]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end0:
    .size	one, .Lfunc_end0-one
    .cfi_endproc
                                        # -- End function
    .globl	two                     # -- Begin function two
    .p2align	4, 0x90
    .type	two,@function
two:                                    # @two
    .cfi_startproc
# %bb.0:
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov	ebx, edi
    lea	rdi, [rip + .L.str.1]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end1:
    .size	two, .Lfunc_end1-two
    .cfi_endproc
                                        # -- End function
    .globl	def                     # -- Begin function def
    .p2align	4, 0x90
    .type	def,@function
def:                                    # @def
    .cfi_startproc
# %bb.0:
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov	ebx, edi
    lea	rdi, [rip + .L.str.4]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end4:
    .size	def, .Lfunc_end4-def
    .cfi_endproc
                                        # -- End function
    .globl	fun                     # -- Begin function fun
    .p2align	4, 0x90
    .type	fun,@function
fun:                                    # @fun
    .cfi_startproc
# %bb.0:
    push	rbp
    .cfi_def_cfa_offset 16
    push	r14
    .cfi_def_cfa_offset 24
    push	rbx
    .cfi_def_cfa_offset 32
    push	r9
    .cfi_offset rbx, -32
    .cfi_offset r14, -24
    .cfi_offset rbp, -16
    mov	ebp, esi
    mov	ebx, edi
    cmp	ebx, ebp
    jge	LBB5_10
# %bb.1:
    lea	r14, [rip + .LJTI5_0]
    .p2align	4, 0x90
LBB5_2:                                # =>This Inner Loop Header: Depth=1
    lea	eax, [rbx - 1]
    cmp	eax, 1
    ja	LBB5_8
# %bb.3:                                #   in Loop: Header=BB5_2 Depth=1
jumping_block:
    movsxd	rax, dword ptr [r14 + 4*rax]
    add	rax, r14
    jmp	rax
LBB5_4:                                #   in Loop: Header=BB5_2 Depth=1
    mov	edi, ebx
    call	one
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_8:                                #   in Loop: Header=BB5_2 Depth=1
    mov	edi, ebx
    call	def
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_5:                                #   in Loop: Header=BB5_2 Depth=1
lea_sym_minus_sym1:
    lea r9, qword ptr [rax + .L3 - LBB5_5]
    cmp rbx, rdi
    jb .L1
lea_sym_minus_sym2:
    lea r9, qword ptr [r9 + .L2 - .L3]
.L1:
    jmp r9
.L2:
    mov	edi, ebx
    call	one
    jmp .L4
.L3:
    mov	edi, ebx
    call	two
.L4:
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_9:                                #   in Loop: Header=BB5_2 Depth=1
    add	ebx, 1
    cmp	ebp, ebx
    jne	LBB5_2
LBB5_10:
    pop	r9
    pop	rbx
    pop	r14
    pop	rbp
    ret
.Lfunc_end5:
    .size	fun, .Lfunc_end5-fun
    .cfi_endproc
    .section	.rodata,"a",@progbits
    .p2align	2

// here we have a table of relative offsets (symbol minus symbol)
.LJTI5_0:
    .long	LBB5_4-.LJTI5_0
    .long	LBB5_5-.LJTI5_0
                                        # -- End function
    .text
    .globl	main                    # -- Begin function main
    .p2align	4, 0x90
    .type	main,@function
main:                                   # @main
    .cfi_startproc
# %bb.0:
    push	rax
    .cfi_def_cfa_offset 16
    lea	rdi, [rip + .L.str.5]
    call	puts@PLT
    mov	edi, 1
    mov	esi, 6
    call	fun
    xor	eax, eax
    pop	rcx
    ret
.Lfunc_end6:
    .size	main, .Lfunc_end6-main
    .cfi_endproc
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

    .type	.L.str.4,@object        # @.str.4
.L.str.4:
    .asciz	"last"
    .size	.L.str.4, 5

    .type	.L.str.5,@object        # @.str.5
.L.str.5:
    .asciz	"!!!Hello World!!!"
    .size	.L.str.5, 18


    .ident	"clang version 6.0.0 (tags/RELEASE_600/final)"
    .section	".note.GNU-stack","",@progbits
