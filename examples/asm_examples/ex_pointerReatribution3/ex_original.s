    // pointer_reatribution3
    // a pointer falls in a different (lower) section
    // the symbol should point to data, not to .got.plt

    .file	"ex_original.c"
    .intel_syntax noprefix
    .section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
    .string	"%i \n"
.LC1:
    .string	"%lu \n"
    .section	.text.unlikely,"ax",@progbits
.LCOLDB2:
    .section	.text.startup,"ax",@progbits
.LHOTB2:
    .p2align 4,,15
    .globl	main
    .type	main, @function
main:
.LFB27:
    .cfi_startproc
    push	rbx
    .cfi_def_cfa_offset 16
    .cfi_offset 3, -16
    mov	edx, 7
    mov	esi, OFFSET FLAT:.LC0
    mov	edi, 1
    xor	eax, eax
    mov	ebx, OFFSET FLAT:state+1320
    call	__printf_chk
    .p2align 4,,10
    .p2align 3
.L2:
    mov	rdx, QWORD PTR [rbx]
    xor	eax, eax
    mov	esi, OFFSET FLAT:.LC1
    mov	edi, 1
    sub	rbx, 88
    call	__printf_chk
    //here is where the pointer reatribution takes place
    cmp	rbx, OFFSET FLAT:state-88
    jne	.L2
    xor	eax, eax
    pop	rbx
    .cfi_def_cfa_offset 8
    ret
    .cfi_endproc
.LFE27:
    .size	main, .-main
    .section	.text.unlikely
.LCOLDE2:
    .section	.text.startup
.LHOTE2:
    .globl	state
    .data
    .align 32
    .type	state, @object
    .size	state, 1408
state:
    .quad	0
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	1
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	2
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	3
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	4
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	5
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	6
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	7
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	8
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	9
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	10
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	11
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	12
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	13
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	14
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .quad	15
    .quad	1
    .quad	2
    .quad	3
    .quad	4
    .quad	5
    .quad	6
    .quad	7
    .quad	8
    .quad	9
    .quad	10
    .ident	"GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609"
    .section	.note.GNU-stack,"",@progbits
