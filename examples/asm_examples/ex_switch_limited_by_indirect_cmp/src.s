  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP
  sub RSP,8
  lea R9,QWORD PTR [RSP]
  lea R13,QWORD PTR [RIP+.L_jumptable]

  sub RDI, 1 # RDI = argc
  mov QWORD PTR [R9], RDI

  cmp QWORD PTR [R9],3
  ja .L_default

.jump:
  mov RAX,QWORD PTR [R9]
  movsxd RAX,DWORD PTR [R13+RAX*4]
  add RAX,R13
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
  add RSP,8
  pop RBP
  ret

.L_default:
  mov EAX, 1
  add RSP,8
  pop RBP
  ret

.L_other:
  mov EAX, 2
  add RSP,8
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
