  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP
  lea R13,QWORD PTR [RIP+.L_jumptable]

  sub RDI, 1 # RDI = argc
  mov RAX, RDI

  cmp RAX,3
  ja .L_default

.jump:
  lea RSI,QWORD PTR [RIP+.L_index_table]
  movzx EAX,BYTE PTR [RSI+RAX*1]
  movsxd RDX,DWORD PTR [R13+RAX*4]
  add RDX,R13
  jmp RDX

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

.section .rodata
.L_index_table:
  .byte (.L_jumptable_1 - .L_jumptable)/4
  .byte (.L_jumptable_2 - .L_jumptable)/4
  .byte (.L_jumptable_3 - .L_jumptable)/4
  .byte (.L_jumptable_4 - .L_jumptable)/4

.L_jumptable:
.L_jumptable_1:
  .long .L_one - .L_jumptable
.L_jumptable_2:
  .long .L_two - .L_jumptable
.L_jumptable_3:
  .long .L_three - .L_jumptable
.L_jumptable_4:
  .long .L_default - .L_jumptable

  # This is a jump table entry that appears valid, but is unreachable due to
  # the available indices in .L_index_table.
  .long .L_other - .L_jumptable

.s_one:
  .asciz "one"
.s_two:
  .asciz "two"
.s_three:
  .asciz "three"
