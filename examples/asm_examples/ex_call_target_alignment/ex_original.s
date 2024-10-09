// This example demonstrates that local function pointers are loaded into
// registers in a switch statment, and a call-reg instruction (call rax)
// indirectly calls one of the functions in a loop.
// The target functions (one, two, three, four and def) need to be aligned
// to avoid any alignment issues even if they are local.

    .text
    .intel_syntax noprefix
    .file	"ex.c"
    .p2align	4, 0x90
    .type	one,@function
one:                                    # @one
    .cfi_startproc
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
    .p2align	4, 0x90
    .type	two,@function
two:                                    # @two
    .cfi_startproc
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
    .p2align	4, 0x90
    .type	three,@function
three:                                  # @three
    .cfi_startproc
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov	ebx, edi
    lea	rdi, [rip + .L.str.2]
    call	puts@PLT
    lea	eax, [rbx + 1]
    pop	rbx
    ret
.Lfunc_end2:
    .size	three, .Lfunc_end2-three
    .cfi_endproc
                                        # -- End function
    .p2align	4, 0x90
    .type	four,@function
four:                                   # @four
    .cfi_startproc
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset rbx, -16
    mov	ebx, edi
    lea	rdi, [rip + .L.str.3]
    call	puts@PLT
    mov	eax, ebx
    pop	rbx
    ret
.Lfunc_end3:
    .size	four, .Lfunc_end3-four
    .cfi_endproc
                                        # -- End function
    .p2align	4, 0x90
    .type	def,@function
def:                                    # @def
    .cfi_startproc
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
    push	rbp
    .cfi_def_cfa_offset 16
    push	r14
    .cfi_def_cfa_offset 24
    push	rbx
    .cfi_def_cfa_offset 32
    .cfi_offset rbx, -32
    .cfi_offset r14, -24
    .cfi_offset rbp, -16
    mov	ebp, esi
    mov	ebx, edi
    cmp	ebx, ebp
    jge	LBB5_10
    lea	r14, [rip + .LJTI5_0]
    .p2align	4, 0x90
LBB5_2:                                # =>This Inner Loop Header: Depth=1
    lea	eax, [rbx - 1]
    cmp	eax, 3
    ja	LBB5_8
jumping_block:
    movsxd	rax, dword ptr [r14 + 4*rax]
    add	rax, r14
    jmp	rax
LBB5_4:                                #   in Loop: Header=BB5_2 Depth=1
    lea rax, [rip + one]
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_8:                                #   in Loop: Header=BB5_2 Depth=1
    lea rax, [rip + def]
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_5:                                #   in Loop: Header=BB5_2 Depth=1
    lea rax, [rip + two]
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_6:                                #   in Loop: Header=BB5_2 Depth=1
    lea rax, [rip + three]
    jmp	LBB5_9
    .p2align	4, 0x90
LBB5_7:                                #   in Loop: Header=BB5_2 Depth=1
    lea rax, [rip + four]
    .p2align	4, 0x90
LBB5_9:                                #   in Loop: Header=BB5_2 Depth=1
    mov	edi, ebx
    call rax
    add	ebx, 1
    cmp	ebp, ebx
    jne	LBB5_2
LBB5_10:
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
    .long	LBB5_6-.LJTI5_0
    .long	LBB5_7-.LJTI5_0
                                        # -- End function
    .text
    .globl	main                    # -- Begin function main
    .p2align	4, 0x90
    .type	main,@function
main:                                   # @main
    .cfi_startproc
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
    .asciz	"last"
    .size	.L.str.4, 5

    .type	.L.str.5,@object        # @.str.5
.L.str.5:
    .asciz	"!!!Hello World!!!"
    .size	.L.str.5, 18


    .ident	"clang version 6.0.0 (tags/RELEASE_600/final)"
    .section	".note.GNU-stack","",@progbits
