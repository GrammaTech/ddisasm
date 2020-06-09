includelib libcmt

public	main
extrn	puts:PROC

.data
message:
	DB	"hello world!", 00H

.code
main:
	sub	rsp, 40

  mov rdx, 3
  call foo

	lea	rcx, OFFSET message
  add rcx, rax
	call	puts

	xor	eax, eax

	add	rsp, 40
	ret	0

foo:
	sub	rsp, 40

  ; label-relative addressing
  lea R8,QWORD PTR [table]
  mov R8,QWORD PTR [R8+RDX*8]   ; table indexing
  lea R9,QWORD PTR [bar]  ; base address
  add R8,R9
  call R8

	add	rsp, 40
	ret	0

bar:
  mov rax, 0
  ret
  nop
  nop
  nop
  nop
  nop

baz:
  mov rax, 1
  ret

qux:
  mov rax, 2
  ret

abc:
  mov rax, 3
  ret

xyz:
  mov rax, 4
  ret

.data
  DB 6 DUP(0FFh)

table:
  QWORD baz - bar
  QWORD qux - bar
  DB 8 DUP(0)
  QWORD abc - bar
  QWORD xyz - bar


END
