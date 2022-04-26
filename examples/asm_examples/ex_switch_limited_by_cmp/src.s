  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP

  mov RAX, RDI  # argc
  sub RAX, 1

  cmp RAX,3
  ja .L_default

.next:
  lea RDI,QWORD PTR [RIP+.L_jumptable]

.jump:
  movsxd RAX,DWORD PTR [RDI+RAX*4]
  add RAX,RDI
  jmp RAX

.L_one:
  mov RDI, OFFSET .s_one
  jmp .L_print

.L_two:
  mov RDI, OFFSET .s_two
  jmp .L_print

.L_three:
  mov RDI, OFFSET .s_three

.L_print:
  call puts@PLT

  xor EAX, EAX
  pop RBP
  ret

.L_default:
  mov EAX, 1
  pop RBP
  ret

.L_other:
  mov EAX, 2
  pop RBP
  ret

.L_jumptable:
  .long .L_one - .L_jumptable
  .long .L_two - .L_jumptable
  .long .L_three - .L_jumptable
  .long .L_default - .L_jumptable

  # This is a jump table entry that appears valid, but is unreachable due to
  # a comparison on the index register.
  .long .L_other - .L_jumptable

  .section .rodata
  .align 4
.s_one:
  .asciz "one"
.s_two:
  .asciz "two"
.s_three:
  .asciz "three"
