	.text

#-----------------------------------
.type __strcmp, @gnu_indirect_function
__strcmp:
#-----------------------------------
.symver strcmp,strcmp@@@GLIBC_2.2.5
.globl strcmp
.type strcmp, @gnu_indirect_function
#-----------------------------------
strcmp:
#-----------------------------------
.type strcmp_ifunc, @function
#-----------------------------------
strcmp_ifunc:

	ret


	.globl  foo
	.type	foo, @function
foo:
.LFB6:
	pushq	%rbp
	movq	%rsp, %rbp
	movl	$20, %esi
	movl	$10, %edi
        # prefer locals to ifunc globals
        # readelf should not contain an entry as follows in .rela.plt:
        # R_X86_64_JUMP_SLO strcmp@@GLIBC_2.2.5() strcmp@@GLIBC_2.2.5 + 0
	call	__strcmp@PLT
	movl	$0, %eax
	popq	%rbp
	ret

.LFE6:
	.size	foo, .-foo
