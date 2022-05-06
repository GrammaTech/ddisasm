  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP

  mov EAX, EDI  # argc
  sub EAX, 1

  cmp EAX,3
  ja .L_default

  # observed this pattern in bzip2 built with gcc -O0
  mov EAX,EAX
  lea RDX,QWORD PTR [RAX*4]
  lea RAX,QWORD PTR [RIP+.L_jumptable]
  mov EAX,DWORD PTR [RDX+RAX*1]
  cdqe
  lea RDX,QWORD PTR [RIP+.L_jumptable]
  add RAX,RDX
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

.section .rodata
.L_jumptable:
  .long .L_one - .L_jumptable
  .long .L_two - .L_jumptable
  .long .L_three - .L_jumptable
  .long .L_default - .L_jumptable

.align 4
.s_one:
  .asciz "one"
.s_two:
  .asciz "two"
.s_three:
  .asciz "three"
