  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  mov     eax, 0

switch:
  mov     eax, eax
  lea     rdx, 0[0+rax*4]
  lea     rax, .L33[rip]
  mov     eax, DWORD PTR [rdx+rax]
  movsxd  rdx, eax
  lea     rax, .L33[rip]
  add     rax, rdx
  jmp     rax

    .section        .rodata
    .align 4
    .align 4

.L33:
.long   .L32-.L33
.long   .L34-.L33
.long   .L35-.L33
.long   .L35-.L33
.long   .L36-.L33

    .text
.L32:
  lea	rdi, [rip + .L.str]
  call	puts@PLT

  mov eax, 1
  jmp switch
.L43:
  mov ebx, 43
  mov eax, 1
  int 0x80
.L34:
  lea	rdi, [rip + .L.str.1]
  call	puts@PLT

  mov eax, 2
  jmp switch
.L35:
  lea	rdi, [rip + .L.str.5]
  call	puts@PLT

  mov eax, 4
  jmp switch
.L36:
  mov ebx, 0
  mov eax, 1
  int 0x80

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
