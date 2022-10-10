	.text
	.globl	table1
	.p2align	4, 0x90
	.type	table1,@function
table1:
	pushl	%ebp
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	subl	$28, %esp
	calll	.L0$pb
.L0$pb:
	popl	%ebx
.Ltmp0:
	addl	$_GLOBAL_OFFSET_TABLE_+(.Ltmp0-.L0$pb), %ebx
	movl	$1, %esi
	leal	.L.str.4@GOTOFF(%ebx), %eax
	movl	%eax, 24(%esp)
	leal	.L.str@GOTOFF(%ebx), %eax
	movl	%eax, 20(%esp)
	leal	.L.str.1@GOTOFF(%ebx), %eax
	movl	%eax, 16(%esp)
	leal	.L.str.2@GOTOFF(%ebx), %ebp
	leal	.L.str.3@GOTOFF(%ebx), %edi
	.p2align	4, 0x90
.LBB0_1:
	movl	%esi, %eax
	andl	$2147483647, %eax
	decl	%eax
	cmpl	$3, %eax
	ja	.LBB0_7
#############################
# FIRST JUMP TABLE PATTERN
	movl	.LJTI0_0@GOTOFF(%ebx,%eax,4), %eax
	addl	%ebx, %eax
	jmpl	*%eax
.LBB0_3:
	movl	20(%esp), %eax
	jmp	.LBB0_8
	.p2align	4, 0x90
.LBB0_7:
	movl	24(%esp), %eax
	jmp	.LBB0_8
	.p2align	4, 0x90
.LBB0_4:
	movl	16(%esp), %eax
.LBB0_8:
	movl	%eax, (%esp)
	jmp	.LBB0_9
	.p2align	4, 0x90
.LBB0_5:
	movl	%ebp, (%esp)
	jmp	.LBB0_9
	.p2align	4, 0x90
.LBB0_6:
	movl	%edi, (%esp)
	.p2align	4, 0x90
.LBB0_9:
	calll	puts@PLT
	incl	%esi
	cmpl	$6, %esi
	jne	.LBB0_1

	addl	$28, %esp
	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp
	retl

	.section	.rodata,"a",@progbits
	.p2align	2
.LJTI0_0:
	.long	.LBB0_3@GOTOFF
	.long	.LBB0_4@GOTOFF
	.long	.LBB0_5@GOTOFF
	.long	.LBB0_6@GOTOFF

	.text
	.globl	table2
	.p2align	4, 0x90
	.type	table2,@function
table2:                                 # @table2

	pushl	%ebp
	pushl	%ebx
	pushl   %ecx
	pushl	%edi
	pushl	%esi
	subl	$28, %esp
	calll	.L1$pb
.L1$pb:
	popl	%ebx
.Ltmp1:
	addl	$_GLOBAL_OFFSET_TABLE_+(.Ltmp1-.L1$pb), %ebx
	movl	$1, %esi
	leal	.L.str.4@GOTOFF(%ebx), %eax
	movl	%eax, 24(%esp)
	leal	.L.str@GOTOFF(%ebx), %eax
	movl	%eax, 20(%esp)
	leal	.L.str.1@GOTOFF(%ebx), %eax
	movl	%eax, 16(%esp)
	leal	.L.str.2@GOTOFF(%ebx), %ebp
	leal	.L.str.3@GOTOFF(%ebx), %edi

	.p2align	4, 0x90
.LBB1_1:
	movl	%esi, %eax
	andl	$2147483647, %eax
	decl	%eax
	cmpl	$3, %eax
	ja	.LBB1_7

	movl      %ebx, %ecx


#############################
# SECOND JUMP TABLE PATTERN

	addl	.LJTI1_0@GOTOFF(%ecx,%eax,4), %ecx
	jmpl	*%ecx
.LBB1_3:
	movl	20(%esp), %eax
	jmp	.LBB1_8
	.p2align	4, 0x90
.LBB1_7:
	movl	24(%esp), %eax
	jmp	.LBB1_8
	.p2align	4, 0x90
.LBB1_4:
	movl	16(%esp), %eax
.LBB1_8:
	movl	%eax, (%esp)
	jmp	.LBB1_9
	.p2align	4, 0x90
.LBB1_5:
	movl	%ebp, (%esp)
	jmp	.LBB1_9
	.p2align	4, 0x90
.LBB1_6:
	movl	%edi, (%esp)
	.p2align	4, 0x90
.LBB1_9:
	calll	puts@PLT
	incl	%esi
	cmpl	$6, %esi
	jne	.LBB1_1
	addl	$28, %esp
	popl	%esi
	popl	%edi
	popl    %ecx
	popl	%ebx
	popl	%ebp
	retl

	.section	.rodata,"a",@progbits
	.p2align	2
.LJTI1_0:
	.long	.LBB1_3@GOTOFF
	.long	.LBB1_4@GOTOFF
	.long	.LBB1_5@GOTOFF
	.long	.LBB1_6@GOTOFF

	.text
	.globl	main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	pushl	%ebx
	subl	$8, %esp
	calll	.L2$pb
.L2$pb:
	popl	%ebx
.Ltmp2:
	addl	$_GLOBAL_OFFSET_TABLE_+(.Ltmp2-.L2$pb), %ebx
	calll	table1
	calll	table2
	xorl	%eax, %eax
	addl	$8, %esp
	popl	%ebx
	retl

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
	.asciz	"def"
	.size	.L.str.4, 4
