.intel_syntax noprefix


.globl foo
.align 16
.type foo, @function
foo:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
        push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
	mov RBP,RSP
        pop RBP
.cfi_def_cfa 7, 8
	ret
# some NOPs
	nop
	nop
	nop
# multiple cfi directives at the end
.cfi_remember_state
.cfi_restore_state
.cfi_endproc


.globl main
.align 16
.type main, @function
main:
.cfi_startproc
.cfi_lsda 255
.cfi_personality 255
.cfi_def_cfa 7, 8
.cfi_offset 16, -8
        push RBP
.cfi_def_cfa_offset 16
.cfi_offset 6, -16
	mov RBP,RSP
	call foo
        pop RBP
.cfi_def_cfa 7, 8
	ret
.cfi_endproc
