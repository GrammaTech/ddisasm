# Regression test
# This pattern was triggering a ddisasm failure because two block candidates
# were awarded identical point totals (when stripped).
.intel_syntax noprefix

.text
.type fun_loop, @function
fun_loop:
	.cfi_startproc
	jmp fun_loop
	.cfi_endproc

.byte 0x66
.byte 0x90
.byte 0x90
.zero 12
break:
# disassembling from here results in different code than the function "fun"
.zero 3

.type fun, @function
fun:
	.cfi_startproc
	mov QWORD PTR [RIP+.label],RDI
	ret
	.cfi_endproc

.global main
.type main, @function
main:
	.cfi_startproc

	// use an address as an immediate to force the nop block above to split
	// into two block candidates.
	mov rax, break

	ret
	.cfi_endproc

.label:

	.quad 0
