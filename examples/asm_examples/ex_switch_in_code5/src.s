  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP

  mov R14, RDI  # argc

  lea R9,QWORD PTR [RIP+.L_jumptable]
  mov R10,R14
  neg R10
  add R10,4
  and R10,3
  je .L_default

  sub R9,QWORD PTR [R9+R10*8]
  jmp R9

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

.align 4
.L_jumptable:
  .quad .L_jumptable - .L_default
  .quad .L_jumptable - .L_three
  .quad .L_jumptable - .L_two
  .quad .L_jumptable - .L_one

  .section .rodata
  .align 4
.s_one:
  .asciz "one"
.s_two:
  .asciz "two"
.s_three:
  .asciz "three"
