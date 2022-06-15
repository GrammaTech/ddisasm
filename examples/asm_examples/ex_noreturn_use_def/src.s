  .intel_syntax noprefix
  .file	"ex.c"

  .text
  .p2align	4, 0x90
  .globl main
  .type	main,@function

main:
  push RBP
  mov RBP,RSP

  mov R15, OFFSET .s_hello_ptr
  mov RDI, R15

  call deref_and_print

  xor RDI, RDI
  cmp RDI, 0
  jz .next

  call my_noreturn

  # This is dead code.
  # If the noreturn is not recognized, def_used from
  # "mov R15, OFFSET .s_hello_ptr" creates a data access at .s_hello_ptr+1,
  # which prevents symbolization of the data object.
  mov AL, [R15 + 1]

.next:
  xor RDI, RDI
  cmp RDI, 0
  jz .next2

  call func_with_tailcall
  mov AL, [R15 + 1]

.next2:
  xor RDI, RDI
  cmp RDI, 0
  jz .do_return

  call my_noreturn_switch
  mov AL, [R15 + 1]

.do_return:
  xor EAX, EAX
  pop RBP
  ret


  .globl func_with_tailcall
  .type	func_with_tailcall,@function
func_with_tailcall:
  mov R15, 3
.loop3:
  sub R15, 1
  jnz .loop3

  # tail call
  jmp my_noreturn_loop

  .globl calls_noreturn_switch
  .type	calls_noreturn_switch,@function
calls_noreturn_switch:
  xor RDI, RDI
  call my_noreturn_switch

  # nops, then fallthrough to another function.
  # ddisasm can infer my_noreturn_switch is noreturn from this.
  nop
  nop
  nop
  nop

  .globl deref_and_print
  .type	deref_and_print,@function
deref_and_print:
  # Dereference a pointer and print
  # This indirection makes it harder for symbolization to identify
  # that there is a data pointer at .s_hello_ptr.
  mov RDI, [RDI]
  call puts@PLT
  ret

  .globl my_noreturn
  .type	my_noreturn,@function
my_noreturn:
  # loop, and then call a known noreturn.
  # The loop ensures noreturn must propagate through loops
  mov R15, 5

.loop:
  mov RDI, OFFSET .s_shutdown
  call puts@PLT

  sub R15, 1
  jnz .loop

  xor RDI, RDI
  call exit@PLT


  .globl my_noreturn_loop
  .type	my_noreturn_loop,@function
my_noreturn_loop:
  push RBP
  mov RBP,RSP

  # jump over some inline data
  jmp .loop_forever

  .long 0xffffffff
  .long 0xffffffff
  .long 0xffffffff
  .long 0xffffffff

  # loop forever
  # The loop ensures noreturn must recognize dead end loops.
.loop_forever:
  mov RDI, OFFSET .s_loop
  call puts@PLT
  jmp .loop_forever

  .globl my_noreturn_switch
  .type	my_noreturn_switch,@function
my_noreturn_switch:
  # enter a switch case, then call a noreturn.
  # segment_target_range can't detect this, but we can guess that it's noreturn
  # if a call to it falls through interprocedurally.
  lea RAX,QWORD PTR [RIP+.L_jumptable]
  movsxd RDI,DWORD PTR [RAX+RDI*4]
  add RDI,RAX
  jmp RDI

.L_one:
    mov RDI, 1
    jmp .L_exit
.L_two:
    mov RDI, 2
.L_exit:
  call exit@PLT

.section .rodata
.align	8, 0x00
.s_hello_ptr:
  .quad .s_hello
.s_hello:
  .asciz "Hello World!"
.s_shutdown:
  .asciz "Shutting down..."
.s_loop:
  .asciz "Loop"

.L_jumptable:
  .long .L_one - .L_jumptable
  .long .L_two - .L_jumptable
