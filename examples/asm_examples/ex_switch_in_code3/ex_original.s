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

done:
  xor eax, eax
  ret

    .section        .rodata
    .align 4
    .align 4

.L33:
.long   .L32-.L33

    .text
.L32:
  lea	rdi, [rip + .L.str]
  call	puts@PLT

  jmp done

.type	.L.str,@object          # @.str
.section	.rodata.str1.1,"aMS",@progbits,1
  .L.str:
.asciz	"one"
.size	.L.str, 4
